import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;


public class partA {
	  
	public static void main(String[] args) {
		final StringBuilder errbuf = new StringBuilder(); // For any error msgs  
		if(args.length<1)
		{
			System.out.println("Please enter the pcap file name!!");
		}
      final String file = args[0];  
      System.out.printf("Opening file for reading: %s%n", file);  
      Pcap pcap = Pcap.openOffline(file, errbuf);
      Tcp tcp = new Tcp();
      if (pcap == null) {  
          System.err.printf("Error while opening device for capture: "  
              + errbuf.toString());  
          return;  
      }  
      PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  

          public void nextPacket(PcapPacket packet, String user) {
          		packetPostmartam(packet);
          	}

			private void packetPostmartam(PcapPacket packet) {
                  if (packet.hasHeader(Tcp.ID)) {  
                      packet.getHeader(tcp);
                    //PART A
                      System.out.println("\n\n ******************************************************************************************\n\n");
                      int flags=packet.getUByte(47);
                      if((flags&0X2) == 0X2)
                      {
                      	System.out.printf("[SYN]");
                      }
                      if((flags&0X1) == 0X1)
                      {
                      	System.out.printf("[FIN]");
                      }
                      if((flags&0X10) == 0X10)
                      {
                      	System.out.printf("[ACK]");
                      }
                      System.out.println("\n");
                      int wind=0;
                      long seq=0;
                      long ack=0;
                      wind=(int) (packet.getUByte(48)*Math.pow(16,2));
                      wind= wind+packet.getUByte(49);
                      
                      seq= (long) (packet.getUByte(38));
                      seq= (long) (seq* Math.pow(16,2)+ packet.getUByte(39));
                      seq= (long) (seq* Math.pow(16,2)+ packet.getUByte(40));
                      seq= (long) (seq* Math.pow(16,2)+ packet.getUByte(41));
                      
                      ack= (long) (packet.getUByte(42));
                      ack= (long) (ack* Math.pow(16,2)+ packet.getUByte(43));
                      ack= (long) (ack* Math.pow(16,2)+ packet.getUByte(44));
                      ack= (long) (ack* Math.pow(16,2)+ packet.getUByte(45));
                      
                      
                      System.out.println(" seq no: "+seq);
                      System.out.println(" ack no: "+ack);
                      System.out.println(" window size : "+wind);


                  }
			}  
      };  
      try {  
          pcap.loop(-1, jpacketHandler, "FCN PART A");

      } finally {  
         pcap.close();  
      }  

	

	}

}