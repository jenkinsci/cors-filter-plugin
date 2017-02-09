package com.appscode.ci.plugins.urlblacklist;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import javax.servlet.http.HttpServletResponse;
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

  @Rule
  public JenkinsRule r = new JenkinsRule();

  AccessControlsFilter.DescriptorImpl descriptor;
  WebClient client;

  @Before
  public void setUp() throws Exception {
    AccessControlsFilter.init();
    descriptor = AccessControlsFilter.DESCRIPTOR;
    client = r.createWebClient();
  }

  @After
  public void tearDown() throws Exception {
    descriptor.setEnabled(false);
  }

  @Test
  public void isValidBlackList() {
    String[] blackList = new String[]{"/user", "/restart" };
    assertTrue(descriptor.isValidBlackList(blackList));

    blackList = new String[]{"user" };
    assertFalse(descriptor.isValidBlackList(blackList));
  }

  @Test
  public void tokenizeBlackList() {
    String blackList = "/user\n     /restart\n\n\n/hello";
    String expectd[] = new String[]{"/user", "/restart", "/hello" };
    descriptor.tokenizeBlackList(blackList);
    assertArrayEquals(expectd, descriptor.tokenizeBlackList(blackList));
  }

  @Test
  public void isBlocked() {
    String blackList[] = new String[]{"/user", "/script" };
    descriptor.setBlackListPrefix(blackList);
    assertTrue(descriptor.isBlocked("/user"));
    assertTrue(descriptor.isBlocked("/user/hell/world"));
    assertTrue(descriptor.isBlocked("/script"));
    assertFalse(descriptor.isBlocked("/scripts/img/url"));
  }

  @Test
  public void testFilter() throws Exception {
    String blackList[] = new String[]{"/userContent", "/restart", "/hello" };
    descriptor.setBlackListPrefix(blackList);
    descriptor.setEnabled(true);

    client.setThrowExceptionOnFailingStatusCode(false);
    assertEquals(HttpServletResponse.SC_FORBIDDEN,
        client.goTo("userContent").getWebResponse().getStatusCode());
    assertEquals(HttpServletResponse.SC_OK, client.goTo("script").getWebResponse().getStatusCode());
    assertEquals(HttpServletResponse.SC_OK,
        client.goTo("configure").getWebResponse().getStatusCode());

    descriptor.doResetDefault();
    //All default restricted link should be forbidden
    for (String link : descriptor.tokenizeBlackList(descriptor.getBlackListPrefix())) {
      assertEquals(HttpServletResponse.SC_FORBIDDEN,
          client.goTo(link.substring(1)).getWebResponse().getStatusCode());
    }
    //Non restricted should allowed
    assertEquals(HttpServletResponse.SC_OK,
        client.goTo("configure").getWebResponse().getStatusCode());
    descriptor.setEnabled(false);
    //Now restricted link should also allowed
    assertEquals(HttpServletResponse.SC_OK,
        client.goTo("userContent").getWebResponse().getStatusCode());
  }
}