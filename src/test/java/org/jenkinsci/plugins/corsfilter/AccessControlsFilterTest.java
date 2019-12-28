package org.jenkinsci.plugins.corsfilter;

import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Test CORS Filter
 * 
 * @author Udaypal Aarkoti
 * @author Steven Christou
 */
public class AccessControlsFilterTest {

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
        descriptor.setAllowedHeaders(null);
        descriptor.setExposedHeaders(null);
        descriptor.setMaxAge(null);
    }

    @Test
    public void testAllowCredentials() throws Exception {
        descriptor.setAllowedMethods("GET, OPTIONS");
        descriptor.setAllowedOrigins("*");
        descriptor.setAllowedHeaders("X-Requested-With");
        descriptor.setExposedHeaders("X-Requested-With");
        descriptor.setMaxAge("999");
        descriptor.setEnabled(true);
        descriptor.reloadAllowedOriginsList();

        client.addRequestHeader("Origin", "*");
        HtmlPage htmlPage = client.goTo("");

        assertTrue(Boolean.valueOf(htmlPage.getWebResponse().getResponseHeaderValue("Access-Control-Allow-Credentials")));
    }

    @Test
    public void testAllowOrigins() throws Exception {
        descriptor.setAllowedOrigins("http://localhost:9000, http://localhost:8080");
        descriptor.setAllowedMethods("GET, OPTIONS");
        descriptor.setAllowedHeaders("X-Requested-With");
        descriptor.setExposedHeaders("X-Requested-With");
        descriptor.setMaxAge("999");
        descriptor.setEnabled(true);
        descriptor.reloadAllowedOriginsList();

        client.addRequestHeader("Origin", "http://localhost:9000");
        HtmlPage htmlPage = client.goTo("");

        assertTrue(Boolean.valueOf(htmlPage.getWebResponse().getResponseHeaderValue("Access-Control-Allow-Credentials")));
        assertEquals(htmlPage.getWebResponse().getResponseHeaderValue("Access-Control-Allow-Origin"), "http://localhost:9000");
        assertEquals(htmlPage.getWebResponse().getResponseHeaderValue("Access-Control-Allow-Headers"), "X-Requested-With");
        assertEquals(htmlPage.getWebResponse().getResponseHeaderValue("Access-Control-Expose-Headers"), "X-Requested-With");
        assertEquals(htmlPage.getWebResponse().getResponseHeaderValue("Access-Control-Max-Age"), "999");
    }

}