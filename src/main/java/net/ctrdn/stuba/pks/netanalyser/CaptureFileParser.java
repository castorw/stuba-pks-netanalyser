package net.ctrdn.stuba.pks.netanalyser;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.ctrdn.stuba.pks.netanalyser.annotation.FrameParser;
import net.ctrdn.stuba.pks.netanalyser.exception.FrameAnalysisException;
import net.ctrdn.stuba.pks.netanalyser.exception.NetAnalyserException;
import net.ctrdn.stuba.pks.netanalyser.exception.ParserFileOpenException;
import net.ctrdn.stuba.pks.netanalyser.exception.UnsupportedSourceFrameTypeException;
import net.ctrdn.stuba.pks.netanalyser.parser.EthernetFrame;
import org.krakenapps.pcap.PcapInputStream;
import org.krakenapps.pcap.file.PcapFileInputStream;
import org.krakenapps.pcap.packet.PcapPacket;
import org.reflections.Reflections;

public class CaptureFileParser {

    private static boolean initialized = false;
    private static Map<Integer, List<Class<? extends EthernetFrame>>> parserMap;
    private final List<EthernetFrame> frameList = new ArrayList<>();

    public final static void initialize() {
        CaptureFileParser.parserMap = new HashMap<>();
        Reflections reflections = new Reflections("net.ctrdn.stuba.pks.netanalyser.parser");
        Set<Class<?>> foundParsers = reflections.getTypesAnnotatedWith(FrameParser.class);
        for (int layer = 2; layer <= 7; layer++) {
            CaptureFileParser.parserMap.put(layer, new ArrayList<Class<? extends EthernetFrame>>());
            for (Class<?> parserClass : foundParsers) {
                try {
                    if (EthernetFrame.class.isAssignableFrom(parserClass)) {
                        if (parserClass.getDeclaredAnnotation(FrameParser.class).layer() == layer) {
                            CaptureFileParser.parserMap.get(layer).add((Class<? extends EthernetFrame>) parserClass);
                        }
                    } else {
                        System.out.println("Class " + parserClass.getName() + " does not extend correct class (invalid parser)");
                    }
                } catch (SecurityException ex) {
                    System.out.println("Parser " + parserClass.getName() + " loading failed - " + ex.getMessage());
                }
            }
            Collections.sort(CaptureFileParser.parserMap.get(layer), new Comparator<Class<? extends EthernetFrame>>() {

                @Override
                public int compare(Class<? extends EthernetFrame> o1, Class<? extends EthernetFrame> o2) {
                    FrameParser a1 = o1.getDeclaredAnnotation(FrameParser.class);
                    FrameParser a2 = o2.getDeclaredAnnotation(FrameParser.class);
                    return a1.orderKey() < a2.orderKey() ? -1 : a1.orderKey() == a2.orderKey() ? 0 : 1;
                }
            });
        }
        CaptureFileParser.initialized = true;
        for (int i = 2; i <= 7; i++) {
            for (Class<? extends EthernetFrame> parserClass : CaptureFileParser.parserMap.get(i)) {
                FrameParser parserAnnotation = parserClass.getDeclaredAnnotation(FrameParser.class);
                System.out.println("Registered L" + parserAnnotation.layer() + " parser " + parserAnnotation.name() + " version " + parserAnnotation.version() + " with order key " + parserAnnotation.orderKey());
            }
        }
    }

    public final static Map<Integer, List<Class<? extends EthernetFrame>>> getParsers() {
        return CaptureFileParser.parserMap;
    }

    public void loadFile(File file) throws ParserFileOpenException, FrameAnalysisException {
        if (!CaptureFileParser.initialized) {
            throw new ParserFileOpenException(this.getClass().getSimpleName() + " is not initialized");
        }
        try {
            PcapInputStream pcapInputStream = new PcapFileInputStream(file);
            try {
                int index = 0;
                while (true) {
                    PcapPacket packet = pcapInputStream.getPacket();
                    EthernetFrame frame = null;
                    for (int layer = 2; layer <= 7; layer++) {
                        boolean layerParsed = false;
                        for (Class<? extends EthernetFrame> parserClass : this.parserMap.get(layer)) {
                            try {
                                if (layer == 2) {
                                    Class[] arguments = new Class[2];
                                    arguments[0] = Integer.class;
                                    arguments[1] = PcapPacket.class;
                                    Constructor parserConstructor = parserClass.getDeclaredConstructor(arguments);
                                    frame = (EthernetFrame) parserConstructor.newInstance(new Object[]{index, packet});
                                } else {
                                    Class[] arguments = new Class[1];
                                    arguments[0] = EthernetFrame.class;
                                    Constructor parserConstructor = parserClass.getDeclaredConstructor(arguments);
                                    frame = (EthernetFrame) parserConstructor.newInstance(new Object[]{frame});
                                }
                                layerParsed = true;
                            } catch (InvocationTargetException ex) {
                                if (ex.getCause().getClass() != UnsupportedSourceFrameTypeException.class) {
                                    if (NetAnalyserException.class.isAssignableFrom(ex.getCause().getClass())) {
                                        throw (NetAnalyserException) ex.getCause();
                                    }
                                }
                            }
                            if (layerParsed) {
                                break;
                            }
                        }
                    }
                    this.frameList.add(frame);
                    index++;
                }
            } catch (EOFException ex) {
            }
        } catch (IOException | NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | NetAnalyserException ex) {
            throw new ParserFileOpenException("(" + ex.getClass().getName() + ") " + ex.getMessage());
        }
    }

    public List<EthernetFrame> getFrameList() {
        return frameList;
    }
}
