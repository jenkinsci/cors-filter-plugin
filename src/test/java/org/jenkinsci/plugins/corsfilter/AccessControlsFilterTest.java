package org.jenkinsci.plugins.corsfilter;

import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

/**
 * Test CORS Filter
 * 
 * @author Udaypal Aarkoti
 * @author Steven Christou
 */
public class AccessControlsFilterTest extends JenkinsRule {

    @Rule public JenkinsRule r = new JenkinsRule();

    AccessControlsFilter.DescriptorImpl descriptor;
    WebClient client;

    @Before
    public void setUp() throws Exception{
        AccessControlsFilter.init();
        descriptor = AccessControlsFilter.DESCRIPTOR;
        client = r.createWebClient();
    }

    @After
    public void tearDown() throws Exception {
        descriptor.setEnabled(false);
    }
}