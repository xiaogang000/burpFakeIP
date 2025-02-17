package burp;

import java.util.Arrays;
import java.util.List;


public class Config {
    public static List<String> HEADER_LIST = Arrays.asList(
            "X-Forwarded-For","X-Forwarded","Forwarded-For","Forwarded","X-Requested-With","X-Forwarded-Proto", "X-Forwarded-Host",
            "X-remote-IP","X-remote-addr","True-Client-IP","X-Client-IP","Client-IP","X-Real-IP",
            "Ali-CDN-Real-IP","Cdn-Src-Ip","Cdn-Real-Ip","CF-Connecting-IP","X-Cluster-Client-IP",
            "WL-Proxy-Client-IP", "Proxy-Client-IP","Fastly-Client-Ip","True-Client-Ip","X-Originating-IP",
            "X-Host","X-Custom-IP-Authorization","X-Api-Version"
    );
    public static List<String> UA_LIST = Arrays.asList(
            "Mozilla/1.22 (compatible; MSIE 2.0d; Windows NT)",
            "Mozilla/2.0 (compatible; MSIE 3.02; Update a; Windows NT)",
            "Mozilla/4.0 (compatible; MSIE 4.01; Windows NT)",
            "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 4.0)",
            "Mozilla/4.79 [en] (WinNT; U)",
            "Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:0.9.2) Gecko/20010726 Netscape6/6.1",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.0.4) Gecko/2008102920 Firefox/3.0.4",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022)",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.19) Gecko/20081204 SeaMonkey/1.1.14",
            "Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaE90-1/210.34.75 Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413",
            "Mozilla/5.0 (iPhone; U; CPU iPhone OS 2_2 like Mac OS X; en-us) AppleWebKit/525.18.1 (KHTML, like Gecko) Version/3.1.1 Mobile/5G77 Safari/525.20",
            "Mozilla/5.0 (Linux; U; Android 1.5; en-gb; HTC Magic Build/CRB17) AppleWebKit/528.5+ (KHTML, like Gecko) Version/3.1.2 Mobile Safari/525.20.1",
            "Opera/9.27 (Windows NT 5.1; U; en)",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.27.1 (KHTML, like Gecko) Version/3.2.1 Safari/525.27.1",
            "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.4.154.25 Safari/525.19",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.48 Safari/525.19",
            "Wget/1.8.2",
            "Mozilla/5.0 (PLAYSTATION 3; 1.00)",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; (R1 1.6))",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.1) Gecko/20061204 Firefox/2.0.0.1",
            "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.0.10) Gecko/2009042316 Firefox/3.0.10 (.NET CLR 3.5.30729) JBroFuzz/1.4",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
            "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20050923 CentOS/1.0.7-1.4.1.centos4 Firefox/1.0.7",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727)",
            "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.0.5) Gecko/2008120122 Firefox/3.0.5",
            "Mozilla/5.0 (X11; U; SunOS i86pc; en-US; rv:1.7) Gecko/20070606",
            "Mozilla/5.0 (X11; U; SunOS i86pc; en-US; rv:1.8.1.14) Gecko/20080520 Firefox/2.0.0.14",
            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.0.5) Gecko/2008120121 Firefox/3.0.5"
    );

    public static boolean AUTOXFF_STAT = false;
    public static String AUTOXFF_KEY = "X-Forwarded-For";
    public static String AUTOXFF_VALUE = "$RandomIp$";

    public static boolean AUTOUA_STAT = false;
    public static String AUTOUA_KEY = "User-Agent";
    public static String AUTOUA_VALUE = "$RandomUA$";
}
