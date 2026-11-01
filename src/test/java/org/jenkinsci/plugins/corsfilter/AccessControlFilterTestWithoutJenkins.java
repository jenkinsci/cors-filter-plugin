package org.jenkinsci.plugins.corsfilter;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AccessControlFilterTestWithoutJenkins {

    @Test
    public void testCreateAllowedOriginsListRemovesWhitespace() {
        List<String> list = AccessControlsFilter.DescriptorImpl.createAllowedOriginsList("foo,bar ,    baz      ,      wibble");

        assertTrue(list.containsAll(List.of("foo", "bar", "baz", "wibble")));
        assertEquals(4, list.size());
    }

}
