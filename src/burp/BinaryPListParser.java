package burp;

/*
 * @(#)BinaryPListParser.java
 *
 * Copyright (c) 2005-2013 Werner Randelshofer, Switzerland.
 * You may not use, copy or modify this file, except in compliance with the
 * accompanying license terms.
 */
import java.io.*;
import java.nio.ByteBuffer;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;
import java.text.*;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

/**
 * Reads a binary PList file and returns it as a NanoXML XMLElement.
 * <p>
 * The NanoXML XMLElement returned by this reader is equivalent to the
 * XMLElement returned, if a PList file in XML format is parsed with
 * NanoXML.
 * <p>
 * Description about property list taken from <a href="http://developer.apple.com/documentation/Cocoa/Conceptual/PropertyLists/index.html#//apple_ref/doc/uid/10000048i">
 * Apple's online documentation</a>:
 * <p>
 * "A property list is a data representation used by Mac OS X Cocoa and Core
 * Foundation as a convenient way to store, organize, and access standard object
 * types. Frequently called a plist, a property list is an object of one of
 * several certain Cocoa or Core Foundation types, including  arrays,
 * dictionaries, strings, binary data, numbers, dates, and Boolean values. If
 * the object is a container (an array or dictionary), all objects contained
 * within it must also be supported property list objects. (Arrays and
 * dictionaries can contain objects not supported by the architecture, but are
 * then not property lists, and cannot be saved and restored with the various
 * property list methods.)"
 *
 * @see ch.randelshofer.quaqua.ext.nanoxml.XMLElement
 *
 * @author  Werner Randelshofer
 * @version $Id$
 */
public class BinaryPListParser {

    private final static boolean DEBUG = false;
    /** Time interval based dates are measured in seconds from 2001-01-01. */
    private final static long TIMER_INTERVAL_TIMEBASE = new GregorianCalendar(2001, 0, 1, 1, 0, 0).getTimeInMillis();
    /** Factory for generating XML data types. */
    private static DatatypeFactory datatypeFactory;

    /* Description of the binary plist format derived from
     * http://opensource.apple.com/source/CF/CF-635/CFBinaryPList.c
     *
     * EBNF description of the file format:
     * <pre>
     * bplist ::= header objectTable offsetTable trailer
     *
     * header ::= magicNumber fileFormatVersion
     * magicNumber ::= "bplist"
     * fileFormatVersion ::= "00"
     *
     * objectTable ::= { null | bool | fill | number | date | data |
     *                 string | uid | array | dict }
     *
     * null  ::= 0b0000 0b0000
     *
     * bool  ::= false | true
     * false ::= 0b0000 0b1000
     * true  ::= 0b0000 0b1001
     *
     * fill  ::= 0b0000 0b1111         // fill byte
     *
     * number ::= int | real
     * int    ::= 0b0001 0bnnnn byte*(2^nnnn)  // 2^nnnn big-endian bytes
     * real   ::= 0b0010 0bnnnn byte*(2^nnnn)  // 2^nnnn big-endian bytes
     *
     * unknown::= 0b0011 0b0000 byte*8       // 8 byte float big-endian bytes ?
     * 
     * date   ::= 0b0011 0b0011 byte*8       // 8 byte float big-endian bytes
     *
     * data   ::= 0b0100 0bnnnn [int] byte*  // nnnn is number of bytes
     *                                       // unless 0b1111 then a int
     *                                       // variable-sized object follows
     *                                       // to indicate the number of bytes
     *
     * string ::= asciiString | unicodeString
     * asciiString   ::= 0b0101 0bnnnn [int] byte*
     * unicodeString ::= 0b0110 0bnnnn [int] short*
     *                                       // nnnn is number of bytes
     *                                       // unless 0b1111 then a int
     *                                       // variable-sized object follows
     *                                       // to indicate the number of bytes
     *
     * uid ::= 0b1000 0bnnnn byte*           // nnnn+1 is # of bytes
     *
     * array ::= 0b1010 0bnnnn [int] objref* //
     *                                       // nnnn is number of objref
     *                                       // unless 0b1111 then a int
     *                                       // variable-sized object follows
     *                                       // to indicate the number of objref
     *
     * dict ::= 0b1010 0bnnnn [int] keyref* objref* 
     *                                       // nnnn is number of keyref and 
     *                                       // objref pairs
     *                                       // unless 0b1111 then a int
     *                                       // variable-sized object follows
     *                                       // to indicate the number of pairs
     *
     * objref = byte | short                 // if refCount
     *                                       // is less than 256 then objref is
     *                                       // an unsigned byte, otherwise it
     *                                       // is an unsigned big-endian short
     *
     * keyref = byte | short                 // if refCount
     *                                       // is less than 256 then objref is
     *                                       // an unsigned byte, otherwise it
     *                                       // is an unsigned big-endian short
     *
     * unused ::= 0b0111 0bxxxx | 0b1001 0bxxxx |
     *            0b1011 0bxxxx | 0b1100 0bxxxx |
     *            0b1110 0bxxxx | 0b1111 0bxxxx
     *
     *
     * offsetTable ::= { int }               // List of ints, byte size of which 
     *                                       // is given in trailer
     *                                       // These are the byte offsets into
     *                                       // the file.
     *                                       // The number of the ffsets is given
     *                                       // in the trailer.
     *
     * trailer ::= refCount offsetCount objectCount topLevelOffset
     *
     * refCount ::= byte*8                  // unsigned big-endian long
     * offsetCount ::= byte*8               // unsigned big-endian long
     * objectCount ::= byte*8               // unsigned big-endian long
     * topLevelOffset ::= byte*8            // unsigned big-endian long
     * </pre>
     */
    /**
     * Total count of objrefs and keyrefs.
     */
    private int refCount;
    /**
     * Object table.
     * We gradually fill in objects from the binary PList object table into
     * this list.
     */
    private ArrayList objectTable;

    /** Holder for a binary PList Uid element. */
    private static class BPLUid {

        private final int number;

        public BPLUid(int number) {
            super();
            this.number = number;
        }

        public int getNumber() {
            return number;
        }
    }

    /**
     * Holder for a binary PList array element.
     */
    private static class BPLArray implements List {

        ArrayList objectTable;
        int[] objref;

        public Object get(int i) {
            return objectTable.get(objref[i]);
        }

		public boolean add(Object o) { throw new UnsupportedOperationException(); }
		public void add(int location, Object o) { throw new UnsupportedOperationException(); }
		public boolean addAll(Collection c) { throw new UnsupportedOperationException(); }
		public boolean addAll(int location, Collection c) { throw new UnsupportedOperationException(); }
		public void clear() { throw new UnsupportedOperationException(); }
		public boolean contains(Object o) { throw new UnsupportedOperationException(); }
		public boolean containsAll(Collection c) { throw new UnsupportedOperationException(); }
		public int indexOf(Object o) { throw new UnsupportedOperationException(); }
		public int lastIndexOf(Object o) { throw new UnsupportedOperationException(); }
		public Iterator iterator() { throw new UnsupportedOperationException(); }
		public ListIterator listIterator(int i) { throw new UnsupportedOperationException(); }
		public ListIterator listIterator() { throw new UnsupportedOperationException(); }
		public Object remove(int i) { throw new UnsupportedOperationException(); }
		public boolean remove(Object o) { throw new UnsupportedOperationException(); }
		public boolean removeAll(Collection c) { throw new UnsupportedOperationException(); }
		public boolean retainAll(Collection c) { throw new UnsupportedOperationException(); }
		public Object set(int location, Object o) { throw new UnsupportedOperationException(); }
		public boolean isEmpty() { return objref.length == 0; }
		public int size() { return objref.length; }
		public List subList(int s, int e) { throw new UnsupportedOperationException(); }
		public Object[] toArray(Object[] a) { throw new UnsupportedOperationException(); }
		public Object[] toArray() { throw new UnsupportedOperationException(); }
    }

    /**
     * Holder for a binary PList dict element.
     */
    private static class BPLDict implements Map<String, Object> {

        ArrayList objectTable;
        int[] keyref;
        int[] objref;

		public void clear() { throw new UnsupportedOperationException(); }
		public boolean containsKey(Object key) { throw new UnsupportedOperationException(); }
		public boolean containsValue(Object value) { throw new UnsupportedOperationException(); }
		public boolean isEmpty() { return keyref.length > 0; }
		public Set<String> keySet() { throw new UnsupportedOperationException(); }
		public Object put(String key, Object value) { throw new UnsupportedOperationException(); }
		public void putAll(Map<? extends String, ? extends Object> map) { throw new UnsupportedOperationException(); }
		public Object remove(Object key) { throw new UnsupportedOperationException(); }
		public int size() { return keyref.length; }
		public Collection<Object> values() { throw new UnsupportedOperationException(); }

		public Object get(Object key) {
			for (int i = 0; i < keyref.length; i++) {
				if (getKey(i).equals(key)) return getValue(i);
			}
			return null;
		}

		public Set<Map.Entry<String, Object>> entrySet() {
			Set<Map.Entry<String, Object>> retval =
				new CopyOnWriteArraySet<Map.Entry<String, Object>>();
			for (int i = 0; i < keyref.length; i++) {
				retval.add(new AbstractMap.SimpleImmutableEntry(getKey(i), getValue(i)));
			}
			return retval;
		}

        public String getKey(int i) {
            return objectTable.get(keyref[i]).toString();
        }

        public Object getValue(int i) {
            return objectTable.get(objref[i]);
        }
    }

    /**
     * Creates a new instance.
     */
    public BinaryPListParser() {
    }

    /**
     * Parses a binary PList file and turns it into a XMLElement.
     * The XMLElement is equivalent with a XML PList file parsed using
     * NanoXML.
     *
     * @param file A file containing a binary PList.
     * @return Returns the parsed XMLElement.
     */
    public Object parse(byte[] raw) throws IOException {
		ByteBuffer bb = ByteBuffer.wrap(raw);
		// Parse the HEADER
		// ----------------
		//  magic number ("bplist")
		//  file format version ("00")
		long bplist00 = bb.getLong();
		if (bplist00 != 0x62706c6973743030L) {
			throw new IOException("parseHeader: File does not start with 'bplist00' magic.");
		}

		// Parse the TRAILER
		// ----------------
		//  count of object refs in arrays and dicts
		refCount = (int) bb.getLong(raw.length - 24);
		//  element # in offset table which is top level object
		int topLevelOffset = (int) bb.getLong(raw.length - 8);
		final byte[] buf = new byte[topLevelOffset - 8];
		bb.position(8);
		bb.get(buf);

        // Parse the OBJECT TABLE
        // ----------------------
        objectTable = new ArrayList();
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(buf))) {
            parseObjectTable(in);
        }

        return objectTable.get(0);
    }
    
    /**
     * Object Formats (marker byte followed by additional info in some cases)
     * null	0000 0000
     * bool	0000 1000			// false
     * bool	0000 1001			// true
     * fill	0000 1111			// fill byte
     * int	0001 nnnn	...		// # of bytes is 2^nnnn, big-endian bytes
     * real	0010 nnnn	...		// # of bytes is 2^nnnn, big-endian bytes
     * date	0011 0011	...		// 8 byte float follows, big-endian bytes
     * data	0100 nnnn	[int]	...	// nnnn is number of bytes unless 1111 then int count follows, followed by bytes
     * string	0101 nnnn	[int]	...	// ASCII string, nnnn is # of chars, else 1111 then int count, then bytes
     * string	0110 nnnn	[int]	...	// Unicode string, nnnn is # of chars, else 1111 then int count, then big-endian 2-byte shorts
     *          0111 xxxx			// unused
     * uid	1000 nnnn	...		// nnnn+1 is # of bytes
     *          1001 xxxx			// unused
     * array	1010 nnnn	[int]	objref*	// nnnn is count, unless '1111', then int count follows
     *          1011 xxxx			// unused
     *          1100 xxxx			// unused
     * dict	1101 nnnn	[int]	keyref* objref*	// nnnn is count, unless '1111', then int count follows
     *          1110 xxxx			// unused
     *          1111 xxxx			// unused
     */
    private void parseObjectTable(DataInputStream in) throws IOException {
        int marker;
        while ((marker = in.read()) != -1) {
            switch ((marker & 0xf0) >> 4) {
                case 0: {
                    parsePrimitive(in, marker & 0xf);
                    break;
                }
                case 1: {
                    int count = 1 << (marker & 0xf);
                    parseInt(in, count);
                    break;
                }
                case 2: {
                    int count = 1 << (marker & 0xf);
                    parseReal(in, count);
                    break;
                }
                case 3: {
                    switch (marker & 0xf) {
                        case 3:
                            parseDate(in);
                            break;
                        default:
                            throw new IOException("parseObjectTable: illegal marker " + Integer.toBinaryString(marker));
                    }
                    break;
                }
                case 4: {
                    int count = marker & 0xf;
                    if (count == 15) {
                        count = readCount(in);
                    }
                    parseData(in, count);
                    break;
                }
                case 5: {
                    int count = marker & 0xf;
                    if (count == 15) {
                        count = readCount(in);
                    }
                    parseAsciiString(in, count);
                    break;
                }
                case 6: {
                    int count = marker & 0xf;
                    if (count == 15) {
                        count = readCount(in);
                    }
                    parseUnicodeString(in, count);
                    break;
                }
                case 7: {
                    if (DEBUG) {
                        System.out.println("parseObjectTable: illegal marker " + Integer.toBinaryString(marker));
                    }
                    return;
                    // throw new IOException("parseObjectTable: illegal marker "+Integer.toBinaryString(marker));
                    //break;
                }
                case 8: {
                    int count = (marker & 0xf) + 1;
                    if (DEBUG) {
                        System.out.println("uid " + count);
                    }
                    parseUID(in, count);
                    break;
                }
                case 9: {
                    throw new IOException("parseObjectTable: illegal marker " + Integer.toBinaryString(marker));
                    //break;
                }
                case 10: {
                    int count = marker & 0xf;
                    if (count == 15) {
                        count = readCount(in);
                    }
                    if (refCount > 255) {
                        parseShortArray(in, count);
                    } else {
                        parseByteArray(in, count);
                    }
                    break;
                }
                case 11: {
                    throw new IOException("parseObjectTable: illegal marker " + Integer.toBinaryString(marker));
                    //break;
                }
                case 12: {
                    throw new IOException("parseObjectTable: illegal marker " + Integer.toBinaryString(marker));
                    //break;
                }
                case 13: {
                    int count = marker & 0xf;
                    if (count == 15) {
                        count = readCount(in);
                    }
                    if (refCount > 256) {
                        parseShortDict(in, count);
                    } else {
                        parseByteDict(in, count);
                    }
                    break;
                }
                case 14: {
                    throw new IOException("parseObjectTable: illegal marker " + Integer.toBinaryString(marker));
                    //break;
                }
                case 15: {
                    throw new IOException("parseObjectTable: illegal marker " + Integer.toBinaryString(marker));
                    //break;
                }
            }
        }
    }

    /**
     * Reads a count value from the object table. Count values are encoded
     * using the following scheme:
     *
     * int	0001 nnnn   ...     // # of bytes is 2^nnnn, big-endian bytes
     */
    private int readCount(DataInputStream in) throws IOException {
        int marker = in.read();
        if (marker == -1) {
            throw new IOException("variableLengthInt: Illegal EOF in marker");
        }
        if (((marker & 0xf0) >> 4) != 1) {
            throw new IOException("variableLengthInt: Illegal marker " + Integer.toBinaryString(marker));
        }
        int count = 1 << (marker & 0xf);
        int value = 0;
        for (int i = 0; i < count; i++) {
            int b = in.read();
            if (b == -1) {
                throw new IOException("variableLengthInt: Illegal EOF in value");
            }
            value = (value << 8) | b;
        }
        return value;
    }

    /**
     * null	0000 0000
     * bool	0000 1000			// false
     * bool	0000 1001			// true
     * fill	0000 1111			// fill byte
     */
    private void parsePrimitive(DataInputStream in, int primitive) throws IOException {
        switch (primitive) {
            case 0:
                objectTable.add(null);
                break;
            case 8:
                objectTable.add(Boolean.FALSE);
                break;
            case 9:
                objectTable.add(Boolean.TRUE);
                break;
            case 15:
                // fill byte: don't add to object table
                break;
            default:
                throw new IOException("parsePrimitive: illegal primitive " + Integer.toBinaryString(primitive));
        }
    }

    /**
     * array	1010 nnnn	[int]	objref*	// nnnn is count, unless '1111', then int count follows
     */
    private void parseByteArray(DataInputStream in, int count) throws IOException {
        BPLArray arr = new BPLArray();
        arr.objectTable = objectTable;
        arr.objref = new int[count];

        for (int i = 0; i < count; i++) {
            arr.objref[i] = in.readByte() & 0xff;
            if (arr.objref[i] == -1) {
                throw new IOException("parseByteArray: illegal EOF in objref*");
            }
        }

        objectTable.add(arr);
    }

    /**
     * array	1010 nnnn	[int]	objref*	// nnnn is count, unless '1111', then int count follows
     */
    private void parseShortArray(DataInputStream in, int count) throws IOException {
        BPLArray arr = new BPLArray();
        arr.objectTable = objectTable;
        arr.objref = new int[count];

        for (int i = 0; i < count; i++) {
            arr.objref[i] = in.readShort() & 0xffff;
            if (arr.objref[i] == -1) {
                throw new IOException("parseShortArray: illegal EOF in objref*");
            }
        }

        objectTable.add(arr);
    }
    /*
     * data	0100 nnnn	[int]	...	// nnnn is number of bytes unless 1111 then int count follows, followed by bytes
     */

    private void parseData(DataInputStream in, int count) throws IOException {
        byte[] data = new byte[count];
        in.readFully(data);
        objectTable.add(data);
    }

    /**
     * byte dict	1101 nnnn keyref* objref*	// nnnn is less than '1111'
     */
    private void parseByteDict(DataInputStream in, int count) throws IOException {
        BPLDict dict = new BPLDict();
        dict.objectTable = objectTable;
        dict.keyref = new int[count];
        dict.objref = new int[count];

        for (int i = 0; i < count; i++) {
            dict.keyref[i] = in.readByte() & 0xff;
        }
        for (int i = 0; i < count; i++) {
            dict.objref[i] = in.readByte() & 0xff;
        }
        objectTable.add(dict);
    }

    /**
     * short dict	1101 ffff int keyref* objref*	// int is count
     */
    private void parseShortDict(DataInputStream in, int count) throws IOException {
        BPLDict dict = new BPLDict();
        dict.objectTable = objectTable;
        dict.keyref = new int[count];
        dict.objref = new int[count];

        for (int i = 0; i < count; i++) {
            dict.keyref[i] = in.readShort() & 0xffff;
        }
        for (int i = 0; i < count; i++) {
            dict.objref[i] = in.readShort() & 0xffff;
        }
        objectTable.add(dict);
    }

    /**
     * string	0101 nnnn	[int]	...	// ASCII string, nnnn is # of chars, else 1111 then int count, then bytes
     */
    private void parseAsciiString(DataInputStream in, int count) throws IOException {
        byte[] buf = new byte[count];
        in.readFully(buf);
        String str = new String(buf, "ASCII");
        objectTable.add(str);
    }

    private void parseUID(DataInputStream in, int count) throws IOException {
        if (count > 4) {
            throw new IOException("parseUID: unsupported byte count: " + count);
        }
        byte[] uid = new byte[count];
        in.readFully(uid);
        objectTable.add(new BPLUid(new BigInteger(uid).intValue()));
    }

    /**
     * int	0001 nnnn	...		// # of bytes is 2^nnnn, big-endian bytes
     */
    private void parseInt(DataInputStream in, int count) throws IOException {
        if (count > 8) {
            throw new IOException("parseInt: unsupported byte count: " + count);
        }
        long value = 0;
        for (int i = 0; i < count; i++) {
            int b = in.read();
            if (b == -1) {
                throw new IOException("parseInt: Illegal EOF in value");
            }
            value = (value << 8) | b;
        }
        objectTable.add(value);
    }

    /**
     * real	0010 nnnn	...		// # of bytes is 2^nnnn, big-endian bytes
     */
    private void parseReal(DataInputStream in, int count) throws IOException {
        switch (count) {
            case 4:
                objectTable.add(new Float(in.readFloat()));
                break;
            case 8:
                objectTable.add(new Double(in.readDouble()));
                break;
            default:
                throw new IOException("parseReal: unsupported byte count:" + count);
        }
    }

    /**
     *  unknown	0011 0000	...		// 8 byte float follows, big-endian bytes
     */
    private void parseUnknown(DataInputStream in) throws IOException {
        in.skipBytes(1);
        objectTable.add("unknown");
    }
    /**
     *  date	0011 0011	...		// 8 byte float follows, big-endian bytes
     */
    private void parseDate(DataInputStream in) throws IOException {
        objectTable.add(fromTimerInterval(in.readDouble()));
    }

    /**
     * string	0110 nnnn	[int]	...	// Unicode string, nnnn is # of chars, else 1111 then int count, then big-endian 2-byte shorts
     */
    private void parseUnicodeString(DataInputStream in, int count) throws IOException {
        char[] buf = new char[count];
        for (int i = 0; i < count; i++) {
            buf[i] = in.readChar();
        }
        String str = new String(buf);
        objectTable.add(str);
    }

    //
    /** Timer interval based dates are measured in seconds from 1/1/2001.
     * Timer intervals have no time zone.
     */
    private static XMLGregorianCalendar fromTimerInterval(double timerInterval) {
        GregorianCalendar gc = new GregorianCalendar();
        gc.setTime(new Date(TIMER_INTERVAL_TIMEBASE + (long) timerInterval * 1000L));
        XMLGregorianCalendar xmlgc = getDatatypeFactory().newXMLGregorianCalendar(gc);
        xmlgc.setFractionalSecond(null);
        xmlgc.setTimezone(DatatypeConstants.FIELD_UNDEFINED);
        return xmlgc;
    }

    /** Gets the factory for XML data types. */
    private static DatatypeFactory getDatatypeFactory() {
        if (datatypeFactory == null) {
            try {
                datatypeFactory = DatatypeFactory.newInstance();
            } catch (DatatypeConfigurationException ex) {
                InternalError ie = new InternalError("Can't create XML datatype factory.");
                ie.initCause(ex);
                throw ie;
            }
        }
        return datatypeFactory;
    }
}
