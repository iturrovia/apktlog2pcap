package apktlog2pcap;

import java.io.File;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.lang.UnsupportedOperationException;

/**
 * LogLineIterator object represents an iteration of log lines, which are
 * eventually read from one or more log files.
 *
 * The purpose of this class is to provide a seamless access to a an iteration
 * of log lines, no matter whethere they are stored in one or many files.
 */
public class LineIterator implements Iterator<String> {
	/*
	 * Instance variables
	 */
	private File file;
	private BufferedReader bufferedReader;
	private String cachedNext;

	/**
	 * Constructor method taking a file as input parameter
	 * The file type is inferred from the byte content
	 * 
	 * @param	file	a text file
	 * @return			the newly created LineIterator object
	 */
	public LineIterator(File file) {
		this.file = file;
		try{
			this.bufferedReader = new BufferedReader(new FileReader(this.file.getPath()));
		} catch(IOException ioe) {
			this.bufferedReader = null;
			throw(new RuntimeException("Failed to create BufferedReader for " + this.file.getPath(), ioe));
		};
		this.cachedNext = null;
	}

	private String getNext() {
		String next = null;
		if(this.cachedNext != null) {
			next = this.cachedNext; // We get the value cached at a previous invocaton of hasNext() method
			this.cachedNext = null; // We consume the cached one so it won't be available in next read
		} else if(this.bufferedReader != null) {
			try{
				next = this.bufferedReader.readLine();
			} catch(IOException ioe) {
				next = null;
				throw(new RuntimeException("IOException while reading line from BufferedReader of " + this.file.getPath(), ioe));
			};
			if(next == null) {
				// Either it is the last line or we got an IOException. Nothing more to read anyway
				try{ this.bufferedReader.close(); } catch(IOException ioe) {};
				this.bufferedReader = null;
			}
		}
		return next;
	}

	/**
	 * Returns true if the iteration has more elements.
	 * (In other words, returns true if next would return an element rather than throwing an exception.)
	 * 
	 * @return	whether the iteration has more elements
	 */
	public boolean hasNext() {
		this.cachedNext = this.getNext();
		return (this.cachedNext != null);
	}

	/**
	 * Returns the next element in the iteration.
	 * 
	 * @return	the next element in the iteration.
	 */
	public String next() {
		String next = this.getNext();
		if(next == null) {
			throw(new NoSuchElementException());
		};
		return next;
	}
	
	/**
	 * Removes from the underlying collection the last element returned by the iterator (optional operation). This method can be called only once per call to next. 
	 * The behavior of an iterator is unspecified if the underlying collection is modified while the iteration is in progress in any way other than by calling this method.
	 * 
	 */
	public void remove() {
		throw(new UnsupportedOperationException());
	}
	
}