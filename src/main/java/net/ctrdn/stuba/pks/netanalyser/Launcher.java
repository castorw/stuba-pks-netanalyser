package net.ctrdn.stuba.pks.netanalyser;

import com.apple.eawt.Application;
import java.awt.Image;
import java.awt.Toolkit;
import javax.swing.UIManager;

public class Launcher {

    public static Image getIconImage() {
        Image iconImage = Toolkit.getDefaultToolkit().createImage(Launcher.class.getResource("/net/ctrdn/stuba/pks/netanalyser/resource/ApplicationIcon.png"));
        Toolkit.getDefaultToolkit().prepareImage(iconImage, -1, -1, null);
        return iconImage;
    }

    public static void main(String args[]) {
        if (System.getProperty("os.name").contains("Mac")) {
            System.setProperty("com.apple.mrj.application.apple.menu.about.name", "PKSPCAPAnalyser");
            Application.getApplication().setEnabledAboutMenu(false);
            Application.getApplication().setEnabledPreferencesMenu(false);
            Application.getApplication().setDockIconImage(Launcher.getIconImage());
        }

        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Launcher.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Launcher.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Launcher.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Launcher.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }

        new AnalyserDialog().setVisible(true);
    }
}
