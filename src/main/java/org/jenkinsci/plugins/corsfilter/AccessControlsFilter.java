package org.jenkinsci.plugins.corsfilter;

import com.google.inject.Injector;
import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.util.PluginServletFilter;
import java.util.Arrays;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.logging.Logger;

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
    private static final Logger LOGGER = Logger.getLogger(AccessControlsFilter.class.getCanonicalName());

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

    /**
     * Handle CORS Access Controls
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (response instanceof HttpServletResponse) {

            final HttpServletResponse resp = (HttpServletResponse) response;
            if (request instanceof HttpServletRequest && getDescriptor().isEnabled()) {
                HttpServletRequest req = (HttpServletRequest) request;
                if (!isAllowed(req.getPathInfo())){
                  resp.sendError(HttpServletResponse.SC_NOT_FOUND);
                  return;
                }
            }
        }
        chain.doFilter(request, response);
    }

    /**
     * Check if path is allowed
     *
     * @param pathInfo
     * @return
     */
    public boolean isAllowed(String pathInfo) {
      if (pathInfo == null) {
        return true;
      }
      String[] prefixBlackList = getDescriptor().getPrefixBlacklist();
      for (int i=0; i<prefixBlackList.length; i++) {
        if (pathInfo.startsWith(prefixBlackList[i])) {
          return false;
        }
      }
      return true;
    }

    @Override
    public void destroy() {

    }

    @Override
    public DescriptorImpl getDescriptor() {
        return DESCRIPTOR;
    }

    public static final class DescriptorImpl extends Descriptor<AccessControlsFilter> {
        private final String[] defaultBlackListPrefix = new String[] {
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
        private String[] prefixBlacklist;
        private boolean enabled;

        public DescriptorImpl() {
            load();
        }

        @Override
        public String getDisplayName() {
            return "URL Filter";
        }

        public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
            enabled = json.getBoolean("enabled");
            String blackList = json.getString("blackList");
            prefixBlacklist = blackList.split("\n");
            save();
            return super.configure(req, json);
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String[] getPrefixBlacklist() {
          if (prefixBlacklist == null) {
            prefixBlacklist = Arrays.copyOf(defaultBlackListPrefix, defaultBlackListPrefix.length);
          }
          return prefixBlacklist;
        }

        public String getBlackList() {
          return String.join("\n", getPrefixBlacklist());
        }

        public void setBlackList(String blackList) {
          prefixBlacklist = blackList.split("\n");
        }

        public void setPrefixBlacklist(String[] prefixBlacklist) { this.prefixBlacklist = prefixBlacklist; }

    }
}
