package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.io.PrintWriter;
import java.util.Random;


public class BurpExtender implements IBurpExtender, IContextMenuFactory, IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator, IHttpListener {
    public static IExtensionHelpers helpers;
    private String PLUGIN_NAME = "burpFakeIP";
    private String VERSION = "1.1";
    public static PrintWriter stdout;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        //通过 callbacks 这个实例对象，传递给插件一系列burp的原生方法。我们需要实现的很多功能都需要调用这些方法。
        helpers = callbacks.getHelpers();

        // 获取burp提供的标准输出流和错误输出流
        stdout = new PrintWriter(callbacks.getStdout(), true);
        //PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
        String banner = "[+] %s %s is loaded...\n" +
                "[+] ####################################\n" +
                "[+]    Anthor: CoolCat\n" +
                "[+]    Blog:   https://blog.thekingofduck.com/\n" +
                "[+]    Github: https://github.com/TheKingOfDuck\n" +
                "[+] ####################################\n" +
                "[+] Enjoy it~";
        // 打印到标准输出流
        stdout.println(String.format(banner, PLUGIN_NAME, VERSION));
        stdout.println("Hello output");

        //注册菜单
        callbacks.registerContextMenuFactory(this);
        callbacks.registerIntruderPayloadGeneratorFactory(this);
        callbacks.registerHttpListener(this);
        // 设置插件的名称
        callbacks.setExtensionName(PLUGIN_NAME);

    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> menus = new ArrayList();
        JMenu menu = new JMenu(PLUGIN_NAME);

        JMenuItem custom = new JMenuItem("customIP");
        JMenuItem localhost = new JMenuItem("127.0.0.1");
        JMenuItem random = new JMenuItem("randomIP");
        JMenuItem autoXFF = new JMenuItem("AutoXFF");
        JMenuItem autoUA = new JMenuItem("AutoUA");

        menu.add(custom);
        menu.add(localhost);
        menu.add(random);
        menu.add(autoXFF);
        menu.add(autoUA);

        if (iContextMenuInvocation.getInvocationContext() != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
            return menus;
        }
        custom.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                String ip = JOptionPane.showInputDialog("Pls input ur ip:");
                Utils.addfakeip(iContextMenuInvocation, ip);
            }
        });

        localhost.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                Utils.addfakeip(iContextMenuInvocation, "127.0.0.1");
            }
        });

        random.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                Utils.addfakeip(iContextMenuInvocation, Utils.getRandomIp());
            }
        });

        autoXFF.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {

                Object[] options = {"OFF", "ON"};
                int flag = JOptionPane.showOptionDialog(null, "AutoXFF Status: " + Config.AUTOXFF_STAT, "FakeIP", JOptionPane.YES_OPTION, JOptionPane.PLAIN_MESSAGE,

                        null, options, options[options.length - 1]);

                switch (flag) {
                    case 0:
                        Config.AUTOXFF_STAT = false;
                        break;
                    case 1:
                        Config.AUTOXFF_KEY = JOptionPane.showInputDialog("Pls input ur XFF header name:", Config.AUTOXFF_KEY);
                        Config.AUTOXFF_VALUE = JOptionPane.showInputDialog("Pls input ur XFF header value:", Config.AUTOXFF_VALUE);
                        Config.AUTOXFF_STAT = true;
                        break;
                    default:
                }
            }
        });
        autoUA.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {

                Object[] options = {"OFF", "ON"};
                int flag = JOptionPane.showOptionDialog(null, "AutoUA Status: " + Config.AUTOUA_STAT, "FakeUA", JOptionPane.YES_OPTION, JOptionPane.PLAIN_MESSAGE,

                        null, options, options[options.length - 1]);
                switch (flag) {
                    case 0:
                        Config.AUTOUA_STAT = false;
                        break;
                    case 1:
                        Config.AUTOUA_VALUE = JOptionPane.showInputDialog("Pls input ur UA header value:", Config.AUTOUA_VALUE);
                        Config.AUTOUA_STAT = true;
                        break;
                    default:
                }
            }
        });
        menus.add(menu);
        return menus;
    }


    @Override
    public boolean hasMorePayloads() {
        return true;
    }

    @Override
    public byte[] getNextPayload(byte[] bytes) {
        String payload = Utils.getRandomIp();
        return payload.getBytes();
    }

    @Override
    public void reset() {

    }

    @Override
    public String getGeneratorName() {
        return PLUGIN_NAME;
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack iIntruderAttack) {
        return this;
    }

    @Override
    public void processHttpMessage(int i, boolean b, IHttpRequestResponse iHttpRequestResponse) {
        if (b && Config.AUTOXFF_STAT) {
            if (Config.AUTOXFF_VALUE.equals("$RandomIp$")) {
                Utils.addfakeip(iHttpRequestResponse, Utils.getRandomIp());
            } else {
                Utils.addfakeip(iHttpRequestResponse, Config.AUTOXFF_VALUE);
            }
        }
        if (b && Config.AUTOUA_STAT) {
            if (Config.AUTOUA_VALUE.equals("$RandomUA$")) {
                Random rand = new Random();
                String ua = Config.UA_LIST.get(rand.nextInt(Config.UA_LIST.size()));
                Utils.addfakeua(iHttpRequestResponse, ua);
            } else {
                Utils.addfakeua(iHttpRequestResponse, Config.AUTOUA_VALUE);
            }
        }
    }
}
