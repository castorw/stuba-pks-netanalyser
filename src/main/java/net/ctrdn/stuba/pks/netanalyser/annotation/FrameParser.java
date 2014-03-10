package net.ctrdn.stuba.pks.netanalyser.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface FrameParser {

    int layer();

    int orderKey();

    String name();

    String version();
}
