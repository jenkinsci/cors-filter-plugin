package org.jenkinsci.plugins.corsfilter;

import com.google.inject.Injector;
import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.util.PluginServletFilter;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.ObjectStreamException;
import java.util.Arrays;
import java.util.Collections;
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
    private static final String PREFLIGHT_REQUEST = "OPTIONS";

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

                /**
                 * If the request is GET, set allow origin
                 * If its pre-flight request, set allow methods
                 */
                processAccessControls(req, resp);

                /**
                 * If this is a preflight request, set the response to 200 OK.
                 */
                if (req.getMethod().equals(PREFLIGHT_REQUEST)) {
                    resp.setStatus(200);
                    return;
                }
            }
        }
        chain.doFilter(request, response);
    }

    /**
     * Apply access controls
     */
    private void processAccessControls(HttpServletRequest req, HttpServletResponse resp) {
        String origin = req.getHeader("Origin");
        if (origin != null && isAllowed(origin.trim())) {
            resp.addHeader("Access-Control-Allow-Credentials", "true");
            resp.addHeader("Access-Control-Allow-Origin", origin);
            resp.addHeader("Access-Control-Allow-Methods", getDescriptor().getAllowedMethods());
            resp.addHeader("Access-Control-Allow-Headers", getDescriptor().getAllowedHeaders());
            resp.addHeader("Access-Control-Expose-Headers", getDescriptor().getExposedHeaders());
            resp.addHeader("Access-Control-Max-Age", getDescriptor().getMaxAge());
        }
    }

    /**
     * Check if the origin is allowed
     *
     * @param origin
     * @return
     */
    private boolean isAllowed(String origin) {
        final List<String> allowedOriginsList = getDescriptor().getAllowedOriginsList();

        /**
         * Asterix (*) means that the resource can be accessed by any domain in a cross-site manner.
         * Should be used with caution.
         */
        if (allowedOriginsList.contains("*")) {
            return true;
        }

        for (int i = 0; i < allowedOriginsList.size(); i++) {
            if (allowedOriginsList.get(i).equals(origin)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public void destroy() {

    }

    @Override
    public DescriptorImpl getDescriptor() {
        return DESCRIPTOR;
    }

    public static final class DescriptorImpl extends Descriptor<AccessControlsFilter> {

        private boolean enabled;
        private String allowedOrigins;
        private String allowedMethods;
        private String allowedHeaders;
        private String exposedHeaders;
        private String maxAge;
        private transient List<String> allowedOriginsList;

        public DescriptorImpl() {
            load();
            allowedOriginsList = createAllowedOriginsList(allowedOrigins);
        }

        @Override
        public String getDisplayName() {
            return "CORS Filter";
        }

        public boolean configure(StaplerRequest req, JSONObject json) throws FormException {

            enabled = json.getBoolean("enabled");
            allowedOrigins = json.getString("allowedOrigins");
            allowedMethods = json.getString("allowedMethods");
            allowedHeaders = json.getString("allowedHeaders");
            exposedHeaders = json.getString("exposedHeaders");
            maxAge = json.getString("maxAge");

            allowedOriginsList = createAllowedOriginsList(allowedOrigins);

            save();
            return super.configure(req, json);
        }

        private List<String> createAllowedOriginsList(String allowedOrigins) {
            final List<String> allowedOriginsList;
            if (allowedOrigins != null && !allowedOrigins.trim().isEmpty()) {
                allowedOriginsList = Arrays.asList(allowedOrigins.split(","));
            } else {
                allowedOriginsList = Collections.EMPTY_LIST;
            }
            return allowedOriginsList;
        }

        void reloadAllowedOriginsList() {
            allowedOriginsList = createAllowedOriginsList(allowedOrigins);
        }

        public List<String> getAllowedOriginsList() {
            return allowedOriginsList;
        }

        public Object readResolve() throws ObjectStreamException {
            createAllowedOriginsList(allowedOrigins);
            return this;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getAllowedOrigins() {
            return allowedOrigins;
        }

        public void setAllowedOrigins(String allowedOrigins) {
            this.allowedOrigins = allowedOrigins;
        }

        public String getAllowedMethods() {
            return allowedMethods;
        }

        public void setAllowedMethods(String allowedMethods) {
            this.allowedMethods = allowedMethods;
        }

        public String getAllowedHeaders() {
            return allowedHeaders;
        }

        public void setAllowedHeaders(String allowedHeaders) {
            this.allowedHeaders = allowedHeaders;
        }

        public String getExposedHeaders() {
            return exposedHeaders;
        }

        public void setExposedHeaders(String exposedHeaders) {
            this.exposedHeaders = exposedHeaders;
        }

        public String getMaxAge() {
            return maxAge;
        }

        public void setMaxAge(String maxAge) {
            this.maxAge = maxAge;
        }
    }
}
