package apktlog2pcap;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import jfnlite.Fn;

/**
 * Command Line Interface for apktlog2pcap
*/
public class Cli extends AppCore {

	/*
	 * return value element
	 */
	public int retValue;
	
	/**
	 * Constructs the Cli object and initializes its return value
	 */
	public Cli() {
		this.retValue = 0;
	}
	
	/**
	 * Writes text console output
	 *
	 * @param	textOutput	the text to output
	 */
	private void consoleOutput(String textOutput){
		System.out.println(textOutput);
	}
	
	/**
	 * Handles Text Output Event
	 *
	 * @param	textOutput	the text to output
	 */
	public void onTextOutput(String textOutput) {
		consoleOutput(textOutput);
	}
	
	/**
	 * Handles User Interface Output
	 *
	 * @param	textOutput	the text to output
	 */
	public void onFinish(int retValue) {
		this.retValue = retValue;
	}
	
	/**
	 * Main method
	 *
	 * @param	args	arguments
	 */
	public static void main(String[] args) {
		String HELP_STRING =
		"apktlog2pcap.v" + Cli.BUILD + ":\r\n" +
		"\r\n" +
		"Usage 1 (converts the input sipmsg file into the output PCAP file):" + "\r\n" +
		"\r\n" +
		"    apktlog2pcap -f <input_file> <output_file>" + "\r\n" +
		"\r\n" +
		"Usage 2 (converts the sipmsg files from the input directory into PCAP files in the output directory):" + "\r\n" +
		"\r\n" +
		"    apktlog2pcap -d <input_directory> <output_directory>" + "\r\n";
		
		List<File> logFilesList = null;
		ArrayList<String> logFilePathList = null;
		String inputFilePath = null;
		String outputFilePath = null;
		String inputDirPath = null;
		String outputDirPath = null;
		byte[] pcapFile = null;
		byte[] fileContents = null;
		//PtmfFile
		File ptmfFile = null;
		String option = null;
		Cli cli = new Cli();
		
		/*
		 * Processing command line args
		 * I wonder why java standard library does not include an implementation for this...
		 */
		if(args.length > 0) {
			option = args[0];
			if(option == "-h") {
				cli.consoleOutput(HELP_STRING);
				cli.retValue = 1;
			} else if((option.equals("-f")) && (args.length == 3)) {
				inputFilePath = args[1];
				outputFilePath = args[2];
				logFilesList = new ArrayList<File>();
				logFilesList.add(new File(inputFilePath));
				cli.processLogFiles(logFilesList, outputFilePath, true, false);
			} else if((option.equals("-d")) && (args.length == 3)) {
				inputDirPath = args[1];
				outputDirPath = args[2];
				cli.processLogFiles(Cli.getLogFiles(inputDirPath, "sipmsg.log"), outputDirPath + "/sipmsg.log.pcap", true, false);
				cli.processLogFiles(Cli.getLogFiles(inputDirPath, "log.sipd"), outputDirPath + "/log.sipd.pcap", false, false);
				cli.processLogFiles(Cli.getLogFiles(inputDirPath, "log.algd"), outputDirPath + "/log.algd.pcap", false, false);
				cli.processLogFiles(Cli.getLogFiles(inputDirPath, "log.mbcd"), outputDirPath + "/log.mbcd.pcap", false, true);
			} else {
				cli.consoleOutput(HELP_STRING);
				cli.retValue = 1;
			};
		} else {
			cli.processLogFiles(Cli.getLogFiles(".", "sipmsg.log"), "sipmsg.log.pcap", true, false);
			cli.processLogFiles(Cli.getLogFiles(".", "log.sipd"), "log.sipd.pcap", false, false);
			cli.processLogFiles(Cli.getLogFiles(".", "log.algd"), "log.algd.pcap", false, false);
			cli.processLogFiles(Cli.getLogFiles(".", "log.mbcd"), "log.mbcd.pcap", false, true);
		};
		System.exit(cli.retValue);
	}
	
}
