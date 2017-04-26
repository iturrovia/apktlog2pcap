package apktlog2pcap;

import java.util.Iterator;
import java.util.NoSuchElementException;
import java.lang.UnsupportedOperationException;
import java.util.List;
import java.util.ArrayList;

public abstract class LogProtoParser<T> {

	public static class LogFrame<T> {
		/*
		 * Instance variables
		 */
		public T parsedHeaderLine;
		public List<String> lines;
	}

	/**
	 * This method parses one line to check whether it is a header line or not, so:
	 * - If it is the header line of a log, it parses it and returns the parsed data in a non-null T object
	 * - If not, then it returns null
	 *
	 * @param	line	the log line to be parsed 
	 * @return			a T object
	 */
	public abstract <T> T parseHeaderLine(String Line);

	/**
	 * This method gets an iterator of lines and returns an iterator of LogFrames:
	 *
	 * @param	lineIterator	the log line iterator
	 * @return					an iterator of LogFrames
	 */
	public <T> Iterator<LogFrame<T>> parse(Iterator<String> lineIterator) {
		return new LogFrameIterator<T>(lineIterator);
	}

	/**
	 * LogFrameIterator object represents an iteration of log frames, which are
	 * eventually read from one or more log files.
	 */
	private class LogFrameIterator<T> implements Iterator<LogFrame<T>> {
		
		/*
		 * Instance variables
		 */
		private Iterator<String> lineIterator;
		private LogFrame<T> cachedNext;
		private String cachedLogLine;
		
		/**
		 * Constructor method taking a byte array as input parameter
		 * The file type is inferred from the byte content
		 * 
		 * @param	lineIterator	an iterator with the log lines
		 * @return				the newly created LogFrameIterator object
		 */
		public LogFrameIterator(Iterator<String> lineIterator) {
			this.lineIterator = lineIterator;
			this.cachedNext = null;
			this.cachedLogLine = null;
		}
		
		private LogFrame<T> getNext() {
			LogFrame<T> next = null;
			T parsedHeaderLine = null;
			String logLine = null;
			
			if(this.cachedNext != null) {
				// We've already read next object from previous invocaton of hasNext() method
				next = this.cachedNext;
				this.cachedNext = null;
			} else {
				/*
				 * We look for the opening header line
				 */
				 // First of all we read the cached log line (if any)
				logLine = this.cachedLogLine;
				if(logLine != null) {
					this.cachedLogLine = null;
					parsedHeaderLine = LogProtoParser.this.parseHeaderLine(logLine);
				};
				// Then we iterate with the next log lines
				while((parsedHeaderLine == null) && (this.lineIterator.hasNext())) {
					logLine = this.lineIterator.next();
					parsedHeaderLine = LogProtoParser.this.parseHeaderLine(logLine);
				};
				/*
				 * Now we should have found the header line if any
				 */
				if(parsedHeaderLine != null) {
					// Found header line, so we create the LogFrame and add the header line
					next = new LogFrame<T>();
					next.parsedHeaderLine = parsedHeaderLine;
					next.lines = new ArrayList<String>();
					next.lines.add(logLine);
					// Now we add extra lines if any
					while(this.lineIterator.hasNext()) {
						logLine = this.lineIterator.next();
						parsedHeaderLine = LogProtoParser.this.parseHeaderLine(logLine);
						if(parsedHeaderLine == null) {
							next.lines.add(logLine);
						} else {
							this.cachedLogLine = logLine;
							break;
						};
					};
					if(!this.lineIterator.hasNext()) {
						this.cachedLogLine = null;
					};
				};
			};
			return next;
		};
		
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
		public LogFrame<T> next() {
			LogFrame<T> next = this.getNext();
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
}
