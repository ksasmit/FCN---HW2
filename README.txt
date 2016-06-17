


			Name : Kumar Sasmit (110308698)
			Homework 2: HTTP, TCP, and Wireshark
			CSE 534, Spring 2016
			Instructor: Aruna Balasubramanian


			
External Libraries used:
--------------------------
Download packages from http://jnetpcap.com/download, both java package and system dll and jar files for windows.

jNetPcap requires WinPcap 3.1 or greater installed. 
                       WinPcap version 4.0.1 or greater is recommended, but not 
                       neccessary. (http://winpcap.org) 
					   
 1) Add supplied jnetpcap-version.jar file to your build system's CLASSPATH.
     The jar file is found at the root of the installation directory in zip 
     files
	 
2) Setup native jnetpcap dynamically loadable library. This varies between
     operating systems.
     
     * On Win32 systems do only one of the following
     
       - copy the jnetpcap.dll library file, found at root of jnetpcap's
         installation directory to one of the window's system folders. This
         could be \windows or \windows\system32 directory.
         
       - add the jNetPcap's installation directory to system PATH variable. This
         is the same variable used access executables and scripts.
         
       - Tell Java VM at startup exactly where to find jnetpcap.dll by setting
         a java system property 'java.library.path' such as:
           c:\> java -Djava.library.path=%JNETPCAP_HOME%
           
       - You can change working directory into the root of jnetpcap's 
         installation directory.
		 
		 
		 
		 
High level view of the design.
--------------------------------
I have divided the source files into three parts as mentioned in the assignment description.
I used wireshark and various references from the web to complete the assignment.
I have extracted most of the fiels from packet headers using the index as shown on wireshark.

Again using byte values, I calculated the various required values like Sequence number, Ack Number, window size, throughut, goodput, Average round trip time, and Initial Congestion window has been computed. All the output results are in the text file attached.

Throughput: Total bytes transferred/ total time taken per connection
Goodput: Total useful bytes transferred except retransmission/ total time taken per connection. I have considered tcp and IP payload values as useful bytes.
Average Round Trip Time: I have considered both timestamp val and echo reply of a packet to calculate the round trip.
Initial Congestion Window: I have referred formula from few web links to calculate the Initial Congestion window using TCP Segment length.

I have used RFC 6298 to compute Part C 2nd question.

Detailed answer to each questions have been attached in separate answer files. 




How to run the programs: <To run the programs the input pcap file must be entered as command line argument>
--------------------------

I used JAVA as my language for the assignment.

Requirements: The system should have JDK installed and system path variables set for java and javac.


The java source files can be compiled and executed by the following steps:
1> put all the files in a single directory.
2>On the command promp go to that directory.
3>execute the following commands
javac -cp <jarfile.jar> <javafile.java>		//generates javafile.class file
java -cp .;<jarfile.jar> <javafile> <args[0]> <args[1]>



***************************************************************************************************************
*		<To run the programs the input pcap file must be entered as command line argument>					  *
***************************************************************************************************************