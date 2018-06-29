package org.jenkinsci.plugins.corsfilter;

import java.util.List;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.junit.Assert.assertThat;

public class AccessControlFilterTestWithoutJenkins {

    @Test
    public void testCreateAllowedOriginsListRemovesWhitespace() {
        List<String> list = AccessControlsFilter.DescriptorImpl.createAllowedOriginsList("foo,bar ,    baz      ,      wibble");

        assertThat(list, hasItems("foo", "bar", "baz", "wibble"));
    }

}
