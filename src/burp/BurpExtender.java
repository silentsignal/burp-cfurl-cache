package burp;

import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.swing.*;
import javax.swing.event.*;
import javax.xml.bind.DatatypeConverter;

public class BurpExtender implements IBurpExtender, ITab, ListSelectionListener, ActionListener {
	private final static BinaryPListParser PARSER = new BinaryPListParser();
	private final static byte[] CRLF = {'\r', '\n'};
	private final static Set<String> SKIP_CONTENT_LENGTH_ENCODING =
		new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
	private final static Set<String> SKIP_NOTHING = Collections.emptySet();
	// TODO use table instead of list
	private final DefaultListModel<Entry> model = new DefaultListModel<Entry>();
	private final JList<Entry> list = new JList<Entry>(model);
	private final JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); 
	private final JTabbedPane tabs = new JTabbedPane();
	private IMessageEditor requestViewer, responseViewer;
	private final EntryProxy proxy = new EntryProxy();
	private IBurpExtenderCallbacks callbacks;

	static {
		SKIP_CONTENT_LENGTH_ENCODING.add("Content-Length");
		SKIP_CONTENT_LENGTH_ENCODING.add("Content-Encoding");
	}

	private static class Entry implements IHttpService {
		public final byte[] request, response;
		private final String host, protocol, verb;
		private final int port;
		private final URL url;
		private final Date timestamp;
		private final short status;

		public Entry(byte[] request, byte[] response, String verb, URL url,
				Date timestamp, short status) {
			this.request = request;
			this.response = response;
			this.verb = verb;
			this.url = url;
			int port = url.getPort();
			if (port == -1) {
				port = url.getProtocol().equalsIgnoreCase("https") ? 443 : 80;
			}
			this.port = port;
			this.host = url.getHost();
			this.protocol = url.getProtocol();
			this.timestamp = timestamp;
			this.status = status;
		}

		public String toString() {
			return String.format("%s | %s %s (%d)", timestamp, verb, url, status);
		}

		public String getHost() { return host; }
		public int getPort() { return port; }
		public String getProtocol() { return protocol; }
	}

	private static class EntryProxy implements IMessageEditorController {
		private Entry target;
		private byte[] EMPTY_BYTE_ARRAY = {};

		public void setTarget(Entry target) { this.target = target; }
		public IHttpService getHttpService() { return target == null ? null : target; }
		public byte[] getRequest() { return target == null ? EMPTY_BYTE_ARRAY : target.request; }
		public byte[] getResponse() { return target == null ? EMPTY_BYTE_ARRAY : target.response; }
	}

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callbacks.setExtensionName("CFURL cache inspector");
		list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		list.addListSelectionListener(this);
		requestViewer = callbacks.createMessageEditor(proxy, false);
		responseViewer = callbacks.createMessageEditor(proxy, false);
		tabs.addTab("Request", requestViewer.getComponent());
		tabs.addTab("Response", responseViewer.getComponent());
		JPanel topPart = new JPanel(new BorderLayout());
		JButton btn = new JButton("Import requests from CFURL Cache.db file");
		btn.addActionListener(this);
		topPart.add(btn, BorderLayout.PAGE_START);
		topPart.add(new JScrollPane(list), BorderLayout.CENTER);
		splitPane.setTopComponent(topPart);
		splitPane.setBottomComponent(tabs);
		callbacks.addSuiteTab(this);
		this.callbacks = callbacks;
	}

	@Override public String getTabCaption() { return "CFURL cache"; }
	@Override public Component getUiComponent() { return splitPane; }

	@Override
	public void valueChanged(ListSelectionEvent e) {
		final Entry entry = model.get(list.getSelectedIndex());
		proxy.setTarget(entry);
		requestViewer.setMessage(entry.request, true);
		responseViewer.setMessage(entry.response, false);
	}

	@Override
	public void actionPerformed(ActionEvent evt) {
		final JFileChooser fileChooser = new JFileChooser();
		if (fileChooser.showOpenDialog(list) == JFileChooser.APPROVE_OPTION) {
			try {
				fillModelFromDatabase(fileChooser.getSelectedFile().getPath());
			} catch (Exception e) {
				e.printStackTrace(new PrintStream(callbacks.getStderr()));
			}
		}
	}

	private void fillModelFromDatabase(final String dbFile) throws IOException,
			SQLException, ClassNotFoundException {
		Class.forName("org.sqlite.JDBC");
		// BLOB is not implemented by SQLite JDBC driver...
		ResultSet rs = DriverManager.getConnection("jdbc:sqlite:" + dbFile)
			.createStatement().executeQuery(
				"SELECT HEX(response_object), HEX(receiver_data), " +
				"HEX(request_object), time_stamp FROM cfurl_cache_blob_data bd " +
				"JOIN cfurl_cache_receiver_data rd ON bd.entry_ID = rd.entry_ID " +
				"JOIN cfurl_cache_response cr ON cr.entry_ID = rd.entry_ID");
		while (rs.next()) {
			// decode request_object
			final List reqInfo = findArrayChildrenInHexPlist(rs.getString(3));
			final String verb = (String)reqInfo.get(18);
			final Object reqData = reqInfo.get(21);
			final byte[] reqBody = reqData instanceof List ? (byte[])((List)reqData).get(0) : null;
			// decode response_object
			final List respInfo = findArrayChildrenInHexPlist(rs.getString(1));
			final URL url = new URL((String)((Map<String, Object>)respInfo.get(0)).get("_CFURLString"));
			final short status = (short)((Long)respInfo.get(3)).longValue();
			final byte[] respBody = decodeHex(rs.getString(2));
			// start printing request
			byte[] req = parseMessage(reqInfo.get(19), SKIP_NOTHING,
					reqBody, "%s %s HTTP/1.1\r\n", verb, url.getFile());
			// start printing response
			byte[] resp = parseMessage(respInfo.get(4), SKIP_CONTENT_LENGTH_ENCODING,
					respBody, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\n",
					status, httpStatusString(status), respBody.length);
			// create entry
			final Date ts = DatatypeConverter.parseDateTime(
					rs.getString(4).replace(' ', 'T')).getTime();
			model.addElement(new Entry(req, resp, verb, url, ts, status));
		}
		rs.close();
	}

	private static byte[] parseMessage(Object src, Set<String> skipSet, byte[] body,
			String headFormat, Object... headParams) throws IOException {
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		final PrintStream ps = new PrintStream(baos);
		ps.printf(headFormat, headParams);
		parseHeaders(ps, src, skipSet);
		ps.flush();
		ps.close();
		baos.write(CRLF);
		if (body != null) baos.write(body);
		return baos.toByteArray();
	}

	private static void parseHeaders(PrintStream ps, Object src, Set<String> skipSet) {
		for (final Map.Entry<String, Object> e : ((Map<String, Object>)src).entrySet()) {
			final String key = e.getKey();
			if (!skipSet.contains(key)) ps.printf("%s: %s\r\n", key, e.getValue());
		}
	}

	private static List findArrayChildrenInHexPlist(final String src) throws IOException {
		return (List)((Map<String, Object>)PARSER.parse(decodeHex(src))).get("Array");
	}

	private static byte[] decodeHex(String s) {
		int length = s.length() / 2;
		byte[] b = new byte[length];
		for (int i = 0; i < length; i++) {
			b[i] = (byte)Short.parseShort(s.substring(i * 2, i * 2 + 2), 16);
		}
		return b;
	}

	private static String httpStatusString(short code) {
		switch (code) {
			case 100: return "Continue";
			case 101: return "Switching Protocols";
			case 200: return "OK";
			case 201: return "Created";
			case 202: return "Accepted";
			case 204: return "No Content";
			case 205: return "Reset Content";
			case 206: return "Partial Content";
			case 300: return "Multiple Choices";
			case 301: return "Moved Permanently";
			case 302: return "Found";
			case 303: return "See Other";
			case 304: return "Not Modified";
			case 305: return "Use Proxy";
			case 307: return "Temporary Redirect";
			case 400: return "Bad Request";
			case 401: return "Unauthorized";
			case 402: return "Payment Required";
			case 403: return "Forbidden";
			case 404: return "Not Found";
			case 405: return "Method Not Allowed";
			case 406: return "Not Acceptable";
			case 407: return "Proxy Authentication Required";
			case 408: return "Request Timeout";
			case 409: return "Conflict";
			case 410: return "Gone";
			case 411: return "Length Required";
			case 412: return "Precondition Failed";
			case 413: return "Request Entity Too Large";
			case 415: return "Unsupported Media Type";
			case 416: return "Requested Range Not Satisfiable";
			case 417: return "Expectation Failed";
			case 500: return "Internal Server Error";
			case 501: return "Not Implemented";
			case 502: return "Bad Gateway";
			case 503: return "Service Unavailable";
			case 504: return "Gateway Timeout";
			default: return "Unknown HTTP Code";
		}
	}
}
