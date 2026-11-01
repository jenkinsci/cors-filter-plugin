package org.jenkinsci.plugins.corsfilter;

import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test CORS Filter
 *
 * @author Udaypal Aarkoti
 * @author Steven Christou
 */
@WithJenkins
public class AccessControlsFilterTest {

    AccessControlsFilter.DescriptorImpl descriptor;
    JenkinsRule.WebClient client;

    @BeforeEach
    public void setUp(JenkinsRule r) throws Exception{
        AccessControlsFilter.init();
        descriptor = AccessControlsFilter.DESCRIPTOR;
        client = r.createWebClient();
    }

    @AfterEach
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
        assertEquals("http://localhost:9000", htmlPage.getWebResponse().getResponseHeaderValue("Access-Control-Allow-Origin"));
        assertEquals("X-Requested-With", htmlPage.getWebResponse().getResponseHeaderValue("Access-Control-Allow-Headers"));
        assertEquals("X-Requested-With", htmlPage.getWebResponse().getResponseHeaderValue("Access-Control-Expose-Headers"));
        assertEquals("999", htmlPage.getWebResponse().getResponseHeaderValue("Access-Control-Max-Age"));
    }

}
