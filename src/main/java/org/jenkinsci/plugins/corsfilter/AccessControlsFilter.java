package org.jenkinsci.plugins.corsfilter;

import com.google.inject.Injector;
import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.util.PluginServletFilter;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;

/**
 * Filter to support <a href="http://en.wikipedia.org/wiki/Cross-origin_resource_sharing">CORS</a>
 * to access Jenkins API's from a dynamic web application using frameworks like AngularJS
 *
 * @author Udaypal Aarkoti
 * @author Steven Christou
 */
@Extension
public class AccessControlsFilter implements Filter, Describable<AccessControlsFilter> {

  @Extension
  public static final DescriptorImpl DESCRIPTOR = new DescriptorImpl();
  private static final Logger LOGGER = Logger
      .getLogger(AccessControlsFilter.class.getCanonicalName());
  private Pattern pattern = Pattern.compile("hello");

  @Initializer(after = InitMilestone.JOB_LOADED)
  public static void init() throws ServletException {
    Injector inj = Jenkins.getInstance().getInjector();
    if (inj == null) {
      return;
    }
    PluginServletFilter.addFilter(inj.getInstance(AccessControlsFilter.class));
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {

  }

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (response instanceof HttpServletResponse) {

      final HttpServletResponse resp = (HttpServletResponse) response;
      if (request instanceof HttpServletRequest && getDescriptor().isEnabled()) {

        HttpServletRequest req = (HttpServletRequest) request;
        if (getDescriptor().isBlocked(req.getPathInfo())) {

          resp.sendError(HttpServletResponse.SC_NOT_FOUND);
          LOGGER.log(Level.INFO, "Request blocked, URL: " + req.getPathInfo());
          return;
        }
      }
    }
    chain.doFilter(request, response);
  }
  
  @Override
  public void destroy() {

  }

  @Override
  public DescriptorImpl getDescriptor() {
    return DESCRIPTOR;
  }

  public static final class DescriptorImpl extends Descriptor<AccessControlsFilter> {

    private Pattern pattern;
    private String[] blackListPrefix = new String[]{
        "/restart",
        "/safeRestart",
        // Disable https://wiki.jenkins-ci.org/display/JENKINS/Jenkins+Script+Console
        "/script",
        "/scriptText",
        "/credential-store",
        "/asynchPeople",
        "/people",
        "/whoAmI",
        "/updateCenter",
        "/pluginManager",
        "/scriptApproval",
        "/log",
        "/credentials",
        "/cli",
        "/about",
        "/user",
    };
    private boolean enabled;

    public DescriptorImpl() {
      load();
    }

    @Override
    public String getDisplayName() {
      return "URL Filter";
    }

    public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
      setEnabled(json.getBoolean("enabled"));
      setBlackList(json.getString("blackList"));
      save();
      return super.configure(req, json);
    }

    public boolean isBlocked(String pathInfo) {
      if (pathInfo == null) {
        return false;
      }
      return pattern.matcher(pathInfo).matches();
    }

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }

    public String getBlackList() {
      return String.join("\n", blackListPrefix);
    }

    public void setBlackList(String blackList) {
      blackList = blackList.replaceAll("\\h", "");
      blackListPrefix = blackList.split("\n");
      compilePattern();
    }

    public void compilePattern() {
      String regex = String.format("(%s)($|/.*)", String.join("|", blackListPrefix));
      pattern = Pattern.compile(regex);
    }
  }
}
