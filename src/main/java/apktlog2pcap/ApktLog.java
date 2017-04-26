package apktlog2pcap;

import java.util.ArrayList;
import java.lang.StringBuilder;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Date;
import java.util.TimeZone;
import java.text.SimpleDateFormat;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Iterator;
import java.net.InetAddress;
import jfnlite.Fn;

/**
 * ApktLog class is a collection of tools to parse APKT logs
 */
public class ApktLog {
	
	private static final String HEADER_LINE_REGEX = "([a-zA-Z]{3})\\s+([0-9]{1,2}) ([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2}).([0-9]{3}) (.*)";
	private static int CAPTURE_GROUP_MONTH = 1;
	private static int CAPTURE_GROUP_DAY = 2;
	private static int CAPTURE_GROUP_HOUR = 3;
	private static int CAPTURE_GROUP_MINUTES = 4;
	private static int CAPTURE_GROUP_SECONDS = 5;
	private static int CAPTURE_GROUP_MILISECONDS = 6;
	private static int CAPTURE_GROUP_GENERICDATA = 7;
	private static final Pattern HEADER_LINE_PATTERN = Pattern.compile(HEADER_LINE_REGEX);
	private static HashMap<String,Integer> MONTH_DICT = new HashMap<String,Integer>();
	
	private static final String END_OF_MESSAGE = "----------------------------------------";
	private static final String VLAN_NETWORK_REGEX = "\\[([0-9]{1,5}):([0-9]{1,5})\\](.*)";
	private static int CAPTURE_GROUP_IFC = 1;
	private static int CAPTURE_GROUP_VLANID = 2;
	private static final Pattern VLAN_NETWORK_PATTERN = Pattern.compile(VLAN_NETWORK_REGEX);
	private static final String IPV4_PORT_REGEX = "([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3}):([0-9]{1,5})";
	private static int CAPTURE_GROUP_IPV4_O1 = 1;
	private static int CAPTURE_GROUP_IPV4_O2 = 2;
	private static int CAPTURE_GROUP_IPV4_O3 = 3;
	private static int CAPTURE_GROUP_IPV4_O4 = 4;
	private static int CAPTURE_GROUP_PORT = 5;
	private static final Pattern IPV4_PORT_PATTERN = Pattern.compile(IPV4_PORT_REGEX);
	
	public static final String LOGFRAMETYPE_SIPMSG_SIP = "SIPMSG_SIP";
	public static final String LOGFRAMETYPE_SIPMSG_LOG = "SIPMSG_LOG";
	public static final String LOGFRAMETYPE_SIPD_LOG = "SIPD_LOG";
	public static final String LOGFRAMETYPE_MBCD_LOG = "MBCD_LOG";
	public static final String LOGFRAMETYPE_ALGD_LOG = "ALGD_LOG";

	public static final String TRANSPORT_UDP = "UDP";
	public static final String TRANSPORT_TCP = "TCP";
	public static final String TRANSPORT_SCTP = "SCTP";
	
	static {
        MONTH_DICT.put("Jan", new Integer(0));
        MONTH_DICT.put("Feb", new Integer(1));
		MONTH_DICT.put("Mar", new Integer(2));
		MONTH_DICT.put("Apr", new Integer(3));
		MONTH_DICT.put("May", new Integer(4));
		MONTH_DICT.put("Jun", new Integer(5));
		MONTH_DICT.put("Jul", new Integer(6));
		MONTH_DICT.put("Aug", new Integer(7));
		MONTH_DICT.put("Sep", new Integer(8));
		MONTH_DICT.put("Oct", new Integer(9));
		MONTH_DICT.put("Nov", new Integer(10));
		MONTH_DICT.put("Dec", new Integer(11));
	}
	
	/**
	 * Creates a date using its year, month, day, hour, minute and second components
	 * 
	 * @param	year	the year component
	 * @param	month	the month component
	 * @param	day		the day component
	 * @param	hour	the hour component
	 * @param	minute	the minute component
	 * @param	second	the second component
	 * @return			the date
	 */
	public static Date createDate(int year, int month, int day, int hours, int minutes, int seconds, TimeZone timeZone) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		sdf.setTimeZone(timeZone);
		String dateInString = Integer.toString(year)+"-"+Integer.toString(month)+"-"+Integer.toString(day)+" "+Integer.toString(hours)+":"+Integer.toString(minutes)+":"+Integer.toString(seconds);
		Date date = null;
		try {
			date = sdf.parse(dateInString);
		} catch (Exception e) {
			// This exception should never take place, but it is mandatory to try-catch
			System.err.println("Exception in createDate:");
			System.err.println(e.toString());
		};
		return date;
	};
	
	public static class ParsedHeaderLine {
		public Date date;
		public int miliseconds;
		public String genericData;
		public InetAddress srcIp = null;
		public InetAddress dstIp = null;
		public int vid = -1;
		public int srcPort = -1;
		public int dstPort = -1;
		public String logFrameType = null;
		
		public String toString() {
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.append(this.date.toString());
			stringBuilder.append('\r');
			stringBuilder.append('\n');
			stringBuilder.append(this.srcIp.toString());
			stringBuilder.append(":");
			stringBuilder.append(String.valueOf(this.srcPort));
			stringBuilder.append('\r');
			stringBuilder.append('\n');
			stringBuilder.append(this.dstIp.toString());
			stringBuilder.append(":");
			stringBuilder.append(String.valueOf(this.dstPort));
			return stringBuilder.toString();
		};
	};
		
	/**
	 * @param	headerLine	The main line
	 * @return	The ParsedHeaderLine object
	 */
	public static ParsedHeaderLine parseHeaderLine(String headerLine) {
		ParsedHeaderLine parsedHeaderLine = null;
		Matcher headerLineMatcher = HEADER_LINE_PATTERN.matcher(headerLine);
		if(headerLineMatcher.matches()) {
			TimeZone timeZone = TimeZone.getDefault();
			int year = (new GregorianCalendar(timeZone)).get(GregorianCalendar.YEAR);
			try {
				parsedHeaderLine = new ParsedHeaderLine();
				parsedHeaderLine.date = createDate(
					year, 
					MONTH_DICT.get(headerLineMatcher.group(CAPTURE_GROUP_MONTH)).intValue(),
					Integer.parseInt(headerLineMatcher.group(CAPTURE_GROUP_DAY)), 
					Integer.parseInt(headerLineMatcher.group(CAPTURE_GROUP_HOUR)), 
					Integer.parseInt(headerLineMatcher.group(CAPTURE_GROUP_MINUTES)), 
					Integer.parseInt(headerLineMatcher.group(CAPTURE_GROUP_SECONDS)), 
					timeZone
				);
				parsedHeaderLine.miliseconds = Integer.parseInt(headerLineMatcher.group(CAPTURE_GROUP_MILISECONDS));
				parsedHeaderLine.genericData = headerLineMatcher.group(CAPTURE_GROUP_GENERICDATA);
				
				try {
					/*
					"Jul  4 11:29:22.360 On [257:888]10.77.68.92:5060 sent to 10.38.2.136:5060";
					"Jul  4 11:29:22.392 On [257:888]10.77.68.92:5060 received from 10.38.2.136:5060";
					*/
					String[] genericDataFields = parsedHeaderLine.genericData.split(" ");
					if(!genericDataFields[0].equals("On")){
						// Not a sipmsg
						throw new Exception();
					};
					Matcher vlanNetworkMatcher = VLAN_NETWORK_PATTERN.matcher(genericDataFields[1]);
					String action = genericDataFields[2];
					parsedHeaderLine.vid = -1;
					String firstIpString = null;
					String secondIpString = null;
					String srcIpString = null;
					String dstIpString = null;
					if(vlanNetworkMatcher.matches()){
						parsedHeaderLine.vid = Integer.parseInt(vlanNetworkMatcher.group(2));
						if(parsedHeaderLine.vid == 0) {
							parsedHeaderLine.vid = -1;
						}
						firstIpString = vlanNetworkMatcher.group(3);
					} else {
						firstIpString = genericDataFields[1];
					};
					secondIpString = genericDataFields[4];
					if(action.equals("sent")){
						srcIpString = firstIpString;
						dstIpString = secondIpString;
					} else {
						srcIpString = secondIpString;
						dstIpString = firstIpString;
					};
					Matcher srcIpv4Matcher = IPV4_PORT_PATTERN.matcher(srcIpString);
					Matcher dstIpv4Matcher = IPV4_PORT_PATTERN.matcher(dstIpString);
					if(srcIpv4Matcher.matches()){
						parsedHeaderLine.srcIp = InetAddress.getByName(srcIpv4Matcher.group(1)+"."+srcIpv4Matcher.group(2)+"."+srcIpv4Matcher.group(3)+"."+srcIpv4Matcher.group(4));
						parsedHeaderLine.srcPort = Integer.parseInt(srcIpv4Matcher.group(5));
					};
					if(dstIpv4Matcher.matches()){
						parsedHeaderLine.dstIp = InetAddress.getByName(dstIpv4Matcher.group(1)+"."+dstIpv4Matcher.group(2)+"."+dstIpv4Matcher.group(3)+"."+dstIpv4Matcher.group(4));
						parsedHeaderLine.dstPort = Integer.parseInt(dstIpv4Matcher.group(5));
					};
					parsedHeaderLine.logFrameType = LOGFRAMETYPE_SIPMSG_SIP;
				} catch (Exception e) {
					// Non-sipmsg message
					parsedHeaderLine.logFrameType = LOGFRAMETYPE_SIPD_LOG;
					parsedHeaderLine.srcIp = InetAddress.getByName("0.0.0.0");
					parsedHeaderLine.dstIp = InetAddress.getByName("0.0.0.0");
					parsedHeaderLine.srcPort = Pcap.UDP_PROTOCOL_SYSLOG;
					parsedHeaderLine.dstPort = Pcap.UDP_PROTOCOL_SYSLOG;
				};
				
				
			} catch (Exception e) {
				parsedHeaderLine = null;
				System.err.println("Exception when parsing the following line:");
				System.err.println(headerLine);
				System.err.println(e.toString());
			};
		};
		return parsedHeaderLine;
	};

	public static abstract class LogFrame {
		public abstract ParsedHeaderLine getParsedHeaderLine();
		public abstract List<String> getLines();
		public String toString() {
			StringBuilder stringBuilder = new StringBuilder();
			for(String line: this.getLines()) {
				stringBuilder.append(line);
			}
			return stringBuilder.toString();
		};
		public String getSipString() {
			return extractSipString(this.getLines());
		};
		public String getTextString() {
			return extractTextString(this.getLines());
		}
		public String inferTransportProtocol() {
			return ApktLog.inferTransportProtocol(this.getLines());
		}
	};

	public static Iterator<LogFrame> parse(Iterator<String> logLines) {
		// We create the protoParser using ApktLog.parseHeaderLine()
		LogProtoParser<ParsedHeaderLine> logProtoParser = new LogProtoParser<ParsedHeaderLine>() {
			public ParsedHeaderLine parseHeaderLine(String line) {
				return ApktLog.parseHeaderLine(line);
			}
		};
		// So we can now get an iterator of ProtoLogFrame objects
		Iterator<LogProtoParser.LogFrame<ParsedHeaderLine>> protoLogFrames = logProtoParser.parse(logLines);
		// Now we define a function to map ProtoLogFrame objects to ApktLog.LogFrame objects
		Fn.Function<LogProtoParser.LogFrame<ParsedHeaderLine>,LogFrame> protoLogFrameToLogFrame = new Fn.Function<LogProtoParser.LogFrame<ParsedHeaderLine>,LogFrame>() {
			public LogFrame apply(final LogProtoParser.LogFrame<ParsedHeaderLine> protoLogFrame) {
				LogFrame logFrame = new LogFrame() {
					public ParsedHeaderLine getParsedHeaderLine() {
						return protoLogFrame.parsedHeaderLine;
					}
					public List<String> getLines() {
						return protoLogFrame.lines;
					}
				};
				return logFrame;
			}
		};
		// So we return an iterator of ApktLog.LogFrame objects
		return Fn.map(protoLogFrames, protoLogFrameToLogFrame);
	}
	
	private static String extractSipString(List<String> lines) {
		StringBuilder stringBuilder = new StringBuilder();
		if(lines.size() > 1) {
			String line = null;
			for(int i=1; i < lines.size(); i++) {
				line = lines.get(i);
				if(!line.equals(END_OF_MESSAGE)){
					stringBuilder.append(line);
					stringBuilder.append('\r');
					stringBuilder.append('\n');
				};
			};
		};
		return stringBuilder.toString();
	};
	
	private static String extractTextString(List<String> lines) {
		StringBuilder stringBuilder = new StringBuilder();
		//stringBuilder.append("[log.sipd] ");
		stringBuilder.append(parseHeaderLine(lines.get(0)).genericData);
		if(lines.size() > 1) {
			String line = null;
			for(int i=1; i < lines.size(); i++) {
				line = lines.get(i);
				if(!line.equals(END_OF_MESSAGE)){
					stringBuilder.append('\r');
					stringBuilder.append('\n');
					stringBuilder.append(line);
				};
			};
		};
		return stringBuilder.toString();
	};

	/**
	 * This method checks whether the content is a SIP message sent over UDP, TCP or SCTP
	 * We can use this to guess whether a SIP message contained in a LogFrame
	 * was sent via UDP, TCP or SCTP (which is an information not present in the sipmsg.log file)
	 * 
	 * @return	The inferred transport protocol
	 */
	private static String inferTransportProtocol(List<String> lines) {
		String transport = TRANSPORT_UDP; // Default
		String sipHeader;
		for(int i=1; i < lines.size(); i++) {
			sipHeader = lines.get(i).toUpperCase();
			if(sipHeader.indexOf("VIA") == 0) {
				if(sipHeader.indexOf("SIP/2.0/UDP") != -1) {
					transport = TRANSPORT_UDP;
				} else if((sipHeader.indexOf("SIP/2.0/TCP") != -1) || (sipHeader.indexOf("SIP/2.0/TLS") != -1)) {
					transport = TRANSPORT_TCP;
				} else if((sipHeader.indexOf("SIP/2.0/SCTP") != -1) || (sipHeader.indexOf("SIP/2.0/TLS-SCTP") != -1)) {
					transport = TRANSPORT_SCTP;
				};
				break;
			};
		}
		return transport;
	}
	
}