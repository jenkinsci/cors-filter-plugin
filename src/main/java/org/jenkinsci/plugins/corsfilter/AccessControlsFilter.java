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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.ArrayList;
import java.util.logging.Logger;
import org.apache.commons.lang.StringUtils;

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
    private List<String> allowedOriginsList = null;
    private List<String> allowedHeadersList = null;

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
            resp.addHeader("Access-Control-Allow-Methods", getDescriptor().getAllowedMethods());
            resp.addHeader("Access-Control-Allow-Credentials", "true");
            resp.addHeader("Access-Control-Allow-Origin", origin);

            /**
             * Requested headers
             */
            String requestedHeaders = req.getHeader("Access-Control-Request-Headers");
            if (requestedHeaders != null && !requestedHeaders.trim().isEmpty()) {
                List<String> acceptedHeadersList = processRequestedHeaders(Arrays.asList(requestedHeaders.split("\\s*,\\s*")));
                if (!acceptedHeadersList.isEmpty()) {
                    // JAVA 8+
                    //resp.addHeader("Access-Control-Allow-Headers", String.join(", ", acceptedHeadersList));
                    // JAVA 7
                    if (acceptedHeadersList.size() == 1) {
                        resp.addHeader("Access-Control-Allow-Headers", acceptedHeadersList.get(0));
                    } else {
                        StringBuilder sb = new StringBuilder();
                        sb.append(acceptedHeadersList.get(0));
                        for (int i = 1; i < acceptedHeadersList.size(); i++) {
                            sb.append(", ").append(acceptedHeadersList.get(i));
                        }
                        resp.addHeader("Access-Control-Allow-Headers", sb.toString());
                    }
                }
            }
        }
    }

    private List<String> processRequestedHeaders(List<String> requestedList) {
        List<String> acceptedList = new ArrayList<String>();

        if (allowedHeadersList == null) {
            String allowedHeaders = getDescriptor().getAllowedHeaders();
            if (allowedHeaders != null && !allowedHeaders.trim().isEmpty()) {
                allowedHeadersList = Arrays.asList(allowedHeaders.split("\\s*,\\s*"));
            } else {
                allowedHeadersList = Collections.EMPTY_LIST;
            }
        }

        for (int i = 0; i < requestedList.size(); i++) {
            if (allowedHeadersList.contains(requestedList.get(i))) {
                acceptedList.add(requestedList.get(i));
            }
        }

        return acceptedList;
    }

    /**
     * Check if the origin is allowed
     *
     * @param origin
     * @return
     */
    private boolean isAllowed(String origin) {

        if (allowedOriginsList == null) {
            String allowedOrigins = getDescriptor().getAllowedOrigins();

            if (allowedOrigins != null && !allowedOrigins.trim().isEmpty()) {
                allowedOriginsList = Arrays.asList(allowedOrigins.split(","));
            } else {
                allowedOriginsList = Collections.EMPTY_LIST;
            }
        }

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

        public DescriptorImpl() {
            load();
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

            save();
            return super.configure(req, json);
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
    }
}
