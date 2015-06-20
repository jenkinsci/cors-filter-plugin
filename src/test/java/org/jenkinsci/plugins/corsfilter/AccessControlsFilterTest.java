package org.jenkinsci.plugins.corsfilter;

import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.Matchers.contains;
import static org.junit.Assert.*;

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
        descriptor.setAllowedOrigins(null);
        descriptor.setEnabled(false);
        descriptor.setAllowedMethods(null);
    }

    @Test
    public void testAllowCredentials() throws Exception {
        descriptor.setAllowedMethods("GET, OPTIONS");
        descriptor.setAllowedOrigins("*");
        descriptor.setEnabled(true);

        client.addRequestHeader("Origin", "*");
        HtmlPage htmlPage = client.goTo("");

        assertTrue(Boolean.valueOf(htmlPage.getWebResponse().getResponseHeaderValue("Access-Control-Allow-Credentials")));
    }

    @Test
    public void testAllowOrigins() throws Exception {
        descriptor.setAllowedMethods("GET, OPTIONS");
        descriptor.setAllowedOrigins("http://localhost:9000, http://localhost:8080");
        descriptor.setEnabled(true);

        client.addRequestHeader("Origin", "http://localhost:9000");
        HtmlPage htmlPage = client.goTo("");

        assertTrue(Boolean.valueOf(htmlPage.getWebResponse().getResponseHeaderValue("Access-Control-Allow-Credentials")));
        assertEquals(htmlPage.getWebResponse().getResponseHeaderValue("Access-Control-Allow-Origin"), "http://localhost:9000");
    }

    @Test
    public void testAllowHeaders() throws Exception {
        descriptor.setAllowedMethods("GET, OPTIONS");
        descriptor.setAllowedOrigins("http://localhost:9000, http://localhost:8080");
        descriptor.setAllowedHeaders("Origin, Content-Type, X-Foo");
        descriptor.setEnabled(true);

        client.addRequestHeader("Origin", "http://localhost:9000");
        client.addRequestHeader("Access-Control-Request-Headers", "Content-Type");
        HtmlPage htmlPage = client.goTo("");

        assertTrue(Boolean.valueOf(htmlPage.getWebResponse().getResponseHeaderValue("Access-Control-Allow-Credentials")));
        assertEquals(htmlPage.getWebResponse().getResponseHeaderValue("Access-Control-Allow-Headers"), "Content-Type");
    }

}