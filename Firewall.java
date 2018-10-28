import java.util.*;
import java.io.BufferedReader;
import java.io.FileReader;
public class Firewall {
    Map<Integer, TreeSet<String>> inboundTCP;   //mapping of port to ip address
    Map<Integer, TreeSet<String>> inboundUDP;
    Map<Integer, TreeSet<String>> outboundTCP;
    Map<Integer, TreeSet<String>> outboundUDP;

    public Firewall(){
        inboundTCP = new HashMap<>();
        inboundUDP = new HashMap<>();
        outboundTCP = new HashMap<>();
        outboundUDP = new HashMap<>();
    }
    public void read(String path){
        try {
            BufferedReader reader = new BufferedReader(new FileReader(path)); //read csv file
            String line = null;
            while((line=reader.readLine())!=null){
                String item[] = line.split(",");
                String direction = item[0];
                String protocol = item[1];
                String port = item[2];
                String ip = item[3];
                if(direction.equals("inbound")) {
                    if (protocol.equals("tcp")) {
                        addRules(inboundTCP, port, ip);
                    }
                    else {
                        addRules(inboundUDP, port, ip);
                    }
                }
                else{
                    if(protocol.equals("tcp")){
                        addRules(outboundTCP, port, ip);
                    }
                    else{
                        addRules(outboundUDP, port, ip);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public void addRules(Map<Integer, TreeSet<String>> map, String port, String ip) { //add each rules to the map
        int startport = 0, endport = 0;
        if (port.indexOf("-") == -1) {
            startport = Integer.parseInt(port);
            endport = startport;
        } else {
            String[] ports = port.split("-");
            startport = Integer.parseInt(ports[0]);
            endport = Integer.parseInt(ports[1]);
        }
        for (int i = startport; i <= endport; i++) {
            if (map.containsKey(i)) {
                map.get(i).add(ip);
            } else {
                TreeSet<String> set = new TreeSet<>(new Comparator<String>() {   //override treemap, order ip address based on start ip
                    @Override
                    public int compare(String o1, String o2) {
                        String[] ip1 = o1.split("-")[0].split("\\.");
                        String[] ip2 = o2.split("-")[0].split("\\.");
                        for (int i = 0; i < 4; i++) {
                            if (Integer.parseInt(ip1[i]) < Integer.parseInt(ip2[i])) {
                                return -1;
                            } else if (Integer.parseInt(ip1[i]) > Integer.parseInt(ip2[i])) {
                                return 1;
                            }
                        }
                        return ip1.length - ip2.length;
                    }
                });
                map.put(i, set);
                map.get(i).add(ip);
            }
        }
    }
    public boolean accept_packet(String direction, String protocol, int port, String ip){
        if(direction.equals("inbound")){
            if(protocol.equals("tcp")){
                return accept(inboundTCP, port, ip);
            }
            else if(protocol.equals("udp")){
                return accept(inboundUDP, port, ip);
            }
            else{
                return false;
            }
        }
        else if(direction.equals("outbound")){
            if(protocol.equals("tcp")){
                return accept(outboundTCP, port, ip);
            }
            else if(protocol.equals("udp")){
                return accept(outboundUDP, port, ip);
            }
            return false;
        }
        return false;
    }
    public boolean accept(Map<Integer, TreeSet<String>> map, int port, String ip){
        if(port<1||port>65535){   //judge whether input port is valid
            return false;
        }
        String [] ipArray = ip.split("\\.");
        if(ipArray.length<4){   //ip address invalid
            return false;
        }
        for(int i=0;i<4;i++){   //judge whether input ip is valid
            if(Integer.parseInt(ipArray[i])<0||Integer.parseInt(ipArray[i])>255){
                return false;
            }
        }
        if(!map.containsKey(port)){    //if the port not in the rule
            return false;
        }
        if(map.get(port).floor(ip)==null){    //if there is no ip range that the start ip is less or equal to ip
            return false;
        }
        if(map.get(port).contains(ip)){       //if exist exact the ip
            return true;
        }
        for(String s:map.get(port)){
            if(s.indexOf("-")==-1){
                continue;
            }
            else {
                String [] range = s.split("-");
                String startIp = range[0];
                String endIp = range[1];
                if(large(startIp, ip)<0){   //ip is smaller than the start of the range, as the set is sorted based on the start ip, so return false
                    return false;
                }
                if(startIp.equals(ip)||endIp.equals(ip)){
                    return true;
                }
                if(large(startIp, ip)>=0&&large(endIp, ip)<=0){//ip in the range
                    return true;
                }
            }
        }

        return false;
    }
    public int large(String ip1, String ip2){   // compare two ip add address
        String [] ip1Array = ip1.split("\\.");
        String [] ip2Array = ip2.split("\\.");
        for(int i=0;i<4;i++){
            int num1 = Integer.parseInt(ip1Array[i]);
            int num2 = Integer.parseInt(ip2Array[i]);
            if(num1<num2){   //ip1 < ip2
                return 1;
            }
            else if(num1>num2){   //ip1 > ip2
                return -1;
            }
        }
        return 0;   //equal
    }
    public static void main(String args[]) {
        Firewall firewall = new Firewall();
        firewall.read("test.csv");
        firewall.addRules(firewall.outboundUDP, "100", "1.1.1.1");  //test add Rules
        firewall.accept(firewall.outboundUDP, 100, "1.1.1.1");  //test accept
        boolean res = firewall.accept_packet("outbound", "tcp", 10000, "192.168.10.11");//rule2
        System.out.println(res);
        res = firewall.accept_packet("inbound", "tcp", 80, "192.168.1.2");  //rule 1
        System.out.println(res);
        res = firewall.accept_packet("inbound", "tcp", 80, "");  //ip address invalid
        System.out.println(res);
        res = firewall.accept_packet("", "tcp", 80, "192.168.10.11");  //direction invalid
        System.out.println(res);
        res = firewall.accept_packet("inbound", "abc", 80, "192.168.10.11");  //protocol
        System.out.println(res);
        res = firewall.accept_packet("outbound", "udp", 73, "192.168.1.5");  //rule 4
        System.out.println(res);
        res = firewall.accept_packet("inbound", "udp", 90, "192.180.90.2");  //rule 3
        System.out.println(res);
    }
}
