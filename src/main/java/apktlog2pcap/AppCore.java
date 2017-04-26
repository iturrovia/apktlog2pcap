package apktlog2pcap;
import jfnlite.Fn;
import java.io.File;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.HashMap;

/**
 * Class implementing the set of functionality requred for apktlog2pcap
 *
 * This class contains the general functionality required for apktlog2pcap
 * and is defined as an abstract one just to be extended by specific user interfaces
 * we might want to create (either command line or graphical user interfaces).
 */
public abstract class AppCore {

	private static final byte[] DEFAULT_MAC = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};

	/** Build version. */
	public static final String BUILD = "0.9.0.build20170426";

	/**
	 * Creates a Predicate checking whether a file name matches the pattern corresponding to a given log type
	 * @param	logType	the log type against which the returned Function will validate 
	 * @return			the resulting Predicate 
	 */
	public static Fn.Predicate<File> isLogFile(final String logType) {
		return new Fn.Predicate<File>() {
			public boolean test(File file) {
				return ( file.isFile() && (file.getName().toUpperCase().matches("(.*)" + logType.toUpperCase() + "\\.?([0-9]*)$")) );
			};
		};
	}
	
	/**
	 * Takes an iterable of log Files, sorts them and returns them in a List
	 * @param	logFiles	iterable of log files 
	 * @return				a list containing the log files in the correct order 
	 */
	public static List<File> sortLogFiles(Iterable<File> logFiles) {
		List<File> sortedLogFileList = new ArrayList<File>();
		List<String> aliasList = new ArrayList<String>();
		HashMap<String,File> logFileMap = new HashMap<String,File>();
		String REGEX = "(.*)\\.([0-9])$";
		String alias;
		for(File file: logFiles){
			if(file.getPath().matches(REGEX)) {
				alias = file.getPath().replaceAll(REGEX, "$1.0$2");
			} else {
				alias = file.getPath();
			};
			aliasList.add(alias);
			logFileMap.put(alias, file);
		}
		java.util.Collections.sort(aliasList, java.util.Collections.reverseOrder());
		for(String key: aliasList) {
			sortedLogFileList.add(logFileMap.get(key));
		};
		return sortedLogFileList;
	}

	/**
	 * Gets a list of all the log files of a specific type than can be found in a specific directory
	 * @param	inputDirPath	path to the input dir
	 * @param	inputType		log type to search 
	 * @return					a List containing the files found 
	 */
	public static List<File> getLogFiles(String inputDirPath, String inputType) {
		File dir = new File(inputDirPath);
		Iterable<File> logFileIterable = Fn.filter(Fn.iterableOf(dir.listFiles()), isLogFile(inputType));
		return sortLogFiles(logFileIterable);
	}

	/**
	 * Converts a LogFrame into a PCAP frame
	 * @param	logFrame	input LogFrame
	 * @return				the PCAP frame 
	 */
	public static Fn.Function<ApktLog.LogFrame,byte[]> logFrameToPcapFrame = new Fn.Function<ApktLog.LogFrame,byte[]>() {
		public byte[] apply(ApktLog.LogFrame logFrame) {
			//ApktLog.ParsedHeaderLine parsedHeaderLine = ApktLog.parseMainLine(logFrame.get(0));
			ApktLog.ParsedHeaderLine parsedHeaderLine = logFrame.getParsedHeaderLine();
			byte[] transportPacket = null;
			byte[] tcpPacket = null;
			byte[] sctpPacket = null;
			byte[] ipPacket = null;
			if(parsedHeaderLine.logFrameType.equals(ApktLog.LOGFRAMETYPE_SIPMSG_SIP)) {
				String sipMessage = logFrame.getSipString();
				String transportProtocol = logFrame.inferTransportProtocol();
				if(transportProtocol == ApktLog.TRANSPORT_UDP) {
					transportPacket = Pcap.createUdpPacket(parsedHeaderLine.srcPort, parsedHeaderLine.dstPort, sipMessage.getBytes());
					ipPacket = Pcap.createIpv4Packet(parsedHeaderLine.srcIp, parsedHeaderLine.dstIp, Pcap.IP_PROTOCOL_UDP, transportPacket);
				} else if(transportProtocol == ApktLog.TRANSPORT_TCP) {
					transportPacket = Pcap.createTcpPacket(parsedHeaderLine.srcPort, parsedHeaderLine.dstPort, sipMessage.getBytes(), parsedHeaderLine.srcIp, parsedHeaderLine.dstIp);
					ipPacket = Pcap.createIpv4Packet(parsedHeaderLine.srcIp, parsedHeaderLine.dstIp, Pcap.IP_PROTOCOL_TCP, transportPacket);
				} else if(transportProtocol == ApktLog.TRANSPORT_SCTP) {
					transportPacket = Pcap.createSctpPacket(parsedHeaderLine.srcPort, parsedHeaderLine.dstPort, sipMessage.getBytes(), parsedHeaderLine.srcIp, parsedHeaderLine.dstIp);
					ipPacket = Pcap.createIpv4Packet(parsedHeaderLine.srcIp, parsedHeaderLine.dstIp, Pcap.IP_PROTOCOL_SCTP, transportPacket);
				} else {
					/*
					 * Incomplete SIP message. This happens when the message has been fragmented, so...
					 * 		- We will assume it was fragmented at TCP (but we are just guessing)
					 *		- If it was fragmented at SCTP or even at IP, Wireshark will not be able to reconstruct the whole SIP message
					 */
					transportPacket = Pcap.createTcpPacket(parsedHeaderLine.srcPort, parsedHeaderLine.dstPort, sipMessage.getBytes(), parsedHeaderLine.srcIp, parsedHeaderLine.dstIp);
					ipPacket = Pcap.createIpv4Packet(parsedHeaderLine.srcIp, parsedHeaderLine.dstIp, Pcap.IP_PROTOCOL_TCP, transportPacket);
				}
			} else {
				transportPacket = Pcap.createUdpPacket(parsedHeaderLine.srcPort, parsedHeaderLine.dstPort, logFrame.getTextString().getBytes());
				ipPacket = Pcap.createIpv4Packet(parsedHeaderLine.srcIp, parsedHeaderLine.dstIp, Pcap.IP_PROTOCOL_UDP, transportPacket);
			};
			byte[] ethernetPacket = Pcap.createEthernetPacket(DEFAULT_MAC, DEFAULT_MAC, Pcap.ETHERTYPE_IPV4, ipPacket, parsedHeaderLine.vid);
			int dateInt = (int) (parsedHeaderLine.date.getTime()/1000);
			byte[] pcapFrame = Pcap.createPcapFrame(dateInt, 1000 * parsedHeaderLine.miliseconds, ethernetPacket.length, ethernetPacket);
			return pcapFrame;
		}
	};
	
	/**
	 * Handles Text Output Event
	 *
	 * @param	textOutput	the text to output
	 */
	public abstract void onTextOutput(String textOutput);
	
	/**
	 * Handles User Interface Output
	 *
	 * @param	textOutput	the text to output
	 */
	public abstract void onFinish(int retValue);

	/**
	 * Writes a stream of byte arrays into the given file.
	 *
	 * @param	bytesIterable	iterable of byte arrays
	 * @param	outputFilePath	path to the output file
	 * @return					the result of the operation
	 */
	private boolean writeToFile(Iterator<byte[]> bytesIterator, String outputFilePath){
		boolean success = false;
		try {
			OutputStream outputStream = null;
			try {
				outputStream = new BufferedOutputStream(new FileOutputStream(outputFilePath));
				while(bytesIterator.hasNext()){
					outputStream.write(bytesIterator.next());
				}
				success = true;
			} finally {
				if(outputStream != null) {
					outputStream.close();
				}
			}
		} catch(FileNotFoundException e){
			onTextOutput("ERROR:  Failed to open output file " + outputFilePath);
		} catch(IOException e){
			onTextOutput("ERROR:  Exception when working with output file " + outputFilePath);
		}
		return success;
	}

	/**
	 * Writes a stream of byte arrays into the given file.
	 *
	 * @param	bytesIterable	iterable of byte arrays
	 * @param	outputFilePath	path to the output file
	 * @return					the result of the operation
	 */
	private boolean writeToFile(Iterable<byte[]> bytesIterable, String outputFilePath){
		return writeToFile(bytesIterable.iterator(), outputFilePath);
	}
	
	/**
	 * Processess a set of log Files, creating a PCAP file and generating events to be handled
	 * by onTextOutput() and onFinished() methods
	 *
	 * @param	logFiles			iterable of log files
	 * @param	outputPcapFilePath	path to the output file
	 * @param	isFirst				whether this is the first set of logFiles to convert to PCAP
	 * @param	isLast				whether this is the last set of logFiles to convert to PCAP
	 * @return						the result of the operation
	 */
	public void processLogFiles(Iterable<File> logFiles, String outputPcapFilePath, boolean isFirst, boolean isLast) {
		String result = null;
		String summary = null;
		int errorCounter = 0;
		/*
		 * Definition of fileToLines function
		 */
		final AppCore that = this; // So we can use a reference to this object in closure below
		Fn.Function<File,Iterator<String>> fileToLines = new Fn.Function<File,Iterator<String>>() {
			public Iterator<String> apply(File file) {
				Iterator<String> lines = null;
				try {
					lines = new LineIterator(file);
				} catch(RuntimeException e) {
					e.printStackTrace();
					that.onTextOutput("================================================================");
					that.onTextOutput(e.toString());
					that.onFinish(1);
				}
				return lines;
			}
		};
		
		if(isFirst) {
			this.onTextOutput("apktlog2pcap.v" + BUILD);
		}

		List<File> logFileList = Fn.collectToList(logFiles);
		if(logFileList.size() > 0 ) {
			this.onTextOutput("================================================================");
			this.onTextOutput("Reading from:");
			for(File file: logFiles) {
				this.onTextOutput(file.getPath());
			};
			Iterator<Iterator<String>> linesIteratorIterator = Fn.map(logFiles.iterator(), fileToLines);
			Iterator<String> logLines = Fn.flatten(linesIteratorIterator);
			Iterator<ApktLog.LogFrame> logFrames = ApktLog.parse(logLines);
			Iterator<byte[]> pcapFrames = Fn.map(logFrames, logFrameToPcapFrame);
			byte[] pcapFileHeader = Pcap.createPcapFileHeader(Pcap.LINKTYPE_ETHERNET);
			this.onTextOutput("Writing to: " + outputPcapFilePath);
			if(writeToFile(Fn.concat(Fn.iteratorOf(pcapFileHeader), pcapFrames), outputPcapFilePath)) {
				result = "OK";
			} else {
				result = "ERROR(FAILED_TO_WRITE_TO_OUTPUT_FILE)";
				errorCounter++;
			};
			this.onTextOutput(result);

			summary = "Processed " + Integer.toString(logFileList.size()) + " files with " + Integer.toString(errorCounter) + " errors";
			this.onTextOutput(summary);
		}

		if(isLast) {
			this.onTextOutput("================================================================");
			this.onFinish(errorCounter);
		}
	}
	
}