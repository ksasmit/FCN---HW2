//package org.jnetpcap;
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

public class partC {

    static HashSet<Long> s= new HashSet<Long>();
    static List<Long> myList = new ArrayList<Long>();
    static long src_port;
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
        Ip4 ip = new Ip4();
        Http http = new Http();
  
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
				// TODO Auto-generated method stub
                    
                    
				if (packet.hasHeader(Tcp.ID) && myList.size() < 20) {
					packet.getHeader(tcp);     
					src_port = tcp.getUByte(0);
					src_port = (long) (src_port * Math.pow(16, 2) + tcp.getUByte(1));
                        packet.getHeader(tcp);

    					long TSval = 0,TSecr=0;
    					TSval = (long) tcp.getUByte(24);
    					TSval = (long) (TSval * Math.pow(16, 2) + tcp.getUByte(25));
    					TSval = (long) (TSval * Math.pow(16, 2) + tcp.getUByte(26));
    					TSval = (long) (TSval * Math.pow(16, 2) + tcp.getUByte(27));

    					TSecr = tcp.getUByte(28);
    					TSecr = (long) (TSecr * Math.pow(16, 2) + tcp.getUByte(29));
    					TSecr = (long) (TSecr * Math.pow(16, 2) + tcp.getUByte(30));
    					TSecr = (long) (TSecr * Math.pow(16, 2) + tcp.getUByte(31));

    					s.add(TSval);
    					if (s.contains(TSecr) && src_port != 80) {
    						long wind = 0;
    						wind = (long) packet.getUByte(48);
    						wind = (long) (wind * Math.pow(16, 2) + packet.getUByte(49));
    						myList.add(wind * 8);

    					}
                       

                    }
			}  
        };  
        try {  
            pcap.loop(-1, jpacketHandler, "Part C");

        } finally {  
			for (int i = 0; i < myList.size(); i++) {
				//System.out.println("congestion #"+(i+1)+" window size "+myList.get(i));
				System.out.println(myList.get(i));
			}
           pcap.close();  
        }  

	}

}
