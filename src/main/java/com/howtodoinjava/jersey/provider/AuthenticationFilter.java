	package com.howtodoinjava.jersey.provider;
	
	import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;

import javax.annotation.security.RolesAllowed;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

import org.glassfish.jersey.internal.util.Base64;
	
	/**
	 * This filter verify the access permissions for a user
	 * based on username and passowrd provided in request
	 * */
	@Provider
	public class AuthenticationFilter implements javax.ws.rs.container.ContainerRequestFilter
	{
		
		@Context
	    private ResourceInfo resourceInfo;
		
	    private static final String AUTHORIZATION_PROPERTY = "Authorization";
	    private static final String AUTHENTICATION_SCHEME = "Basic";
	    /*private static final Response ACCESS_DENIED = Response.status(Response.Status.UNAUTHORIZED)
	    													.entity("You cannot access this resource").build();
	    */private static final Response ACCESS_FORBIDDEN = Response.status(Response.Status.FORBIDDEN)
	    													.entity("Access blocked for all users !!").build();

		private static final String ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods";

		private static final String ACCESS_CONTROL_REQUEST_HEADERS = "Access-Control-Request-Headers";

		private static final String ACCESS_CONTROL_ALLOW_HEADERS = "Access-Control-Allow-Headers";

		private static final String ACCESS_CONTROL_MAX_AGE = "Access-Control-Max-Age";
		
		private static final String ACCESS_CONTROL_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";
		private static final String ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
		private static final String ACCESS_CONTROL_REQUEST_METHOD = "Access-Control-Request-Method";
		private static final String ORIGIN = "Origin";
	     
	    
	    protected boolean allowCredentials = true;
	    protected String allowedMethods;
	    protected String allowedHeaders;
	    protected String exposedHeaders;
	    protected int corsMaxAge = 86400;
	    protected Set<String> allowedOrigins = new HashSet<String>();
	    
	    
	    @Override
	    public void filter(ContainerRequestContext requestContext) throws IOException
	    {
	        Method method = resourceInfo.getResourceMethod();
	        //Access allowed for all
	        /*if( ! method.isAnnotationPresent(PermitAll.class))
	        {*/
	            //Access denied for all
	           /* if(method.isAnnotationPresent(DenyAll.class))
	            {
	                requestContext.abortWith(ACCESS_FORBIDDEN);
	                return;
	            }*/
	       
	        
	            //Get request headers
	        String origin = requestContext.getHeaderString(ORIGIN);
	            final MultivaluedMap<String, String> headers = requestContext.getHeaders();
	             
	            Response ACCESS_DENIED = Response.status(Response.Status.UNAUTHORIZED)
						.entity("You cannot access this resource").header(ACCESS_CONTROL_ALLOW_ORIGIN, origin).build();
		        String methodName = requestContext.getMethod();
		        if("OPTIONS".equalsIgnoreCase(methodName)){
		        	System.out.println("options method called");
		        	/* Response OPTION_RESPONSE = Response.status(Response.Status.UNAUTHORIZED)
		 					.entity("Preflight options has called").build();
		        	 requestContext.abortWith(OPTION_RESPONSE);*/
		        	
						try {
							preflight(origin, requestContext);
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					
		                return;
		        }
	            //Fetch authorization header
	            final List<String> authorization = headers.get(AUTHORIZATION_PROPERTY);
	             
	            //If no authorization information present; block access
	            if(authorization == null || authorization.isEmpty())
	            {
	                requestContext.abortWith(ACCESS_DENIED);
	                return;
	            }
	             
	            //Get encoded username and password
	            final String encodedUserPassword = authorization.get(0).replaceFirst(AUTHENTICATION_SCHEME + " ", "");
	             
	            //Decode username and password
	            //String usernameAndPassword = new String(Base64.decode(encodedUserPassword.getBytes()));;
	 
	            //Split username and password tokens
	            final StringTokenizer tokenizer = new StringTokenizer(encodedUserPassword, ":");
	            final String username = tokenizer.nextToken();
	            final String password = tokenizer.nextToken();
	             
	            //Verifying Username and password
	            System.out.println(username);
	            System.out.println(password);
	             
	            //Verify user access
	           /* if(method.isAnnotationPresent(RolesAllowed.class))
	            {
	                RolesAllowed rolesAnnotation = method.getAnnotation(RolesAllowed.class);
	                Set<String> rolesSet = new HashSet<String>(Arrays.asList(rolesAnnotation.value()));
	                 
	                //Is user valid?
	                if( ! isUserAllowed(username, password, rolesSet))
	                {
	                    requestContext.abortWith(ACCESS_DENIED);
	                    return;
	                }
	            }*/
	        //}
	    }
	    
	    protected void preflight(String origin, ContainerRequestContext requestContext) throws Exception
	    {
	       //checkOrigin(requestContext, origin);

	       Response.ResponseBuilder builder = Response.ok();
	       builder.header(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
	       if (allowCredentials) builder.header(ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
	       String requestMethods = requestContext.getHeaderString(ACCESS_CONTROL_REQUEST_METHOD);
	       if (requestMethods != null)
	       {
	          if (allowedMethods != null)
	          {
	             requestMethods = this.allowedMethods;
	          }
	          builder.header(ACCESS_CONTROL_ALLOW_METHODS, requestMethods);
	       }
	       String allowHeaders = requestContext.getHeaderString(ACCESS_CONTROL_REQUEST_HEADERS);
	       if (allowHeaders != null)
	       {
	          if (allowedHeaders != null)
	          {
	             allowHeaders = this.allowedHeaders;
	          }
	          builder.header(ACCESS_CONTROL_ALLOW_HEADERS, allowHeaders);
	       }
	      /* String corsMaxAge = requestContext.getHeaderString(ACCESS_CONTROL_MAX_AGE);
	       if(corsMaxAge!=null && !corsMaxAge.equals("")){
	    	   System.out.println("corsMAxage is :"+corsMaxAge);
	    	   try{
	    		   int crosMaxAgeInteger = Integer.parseInt(corsMaxAge);
	    		   if (crosMaxAgeInteger > -1)
	    	       {*/
	    	          builder.header(ACCESS_CONTROL_MAX_AGE, corsMaxAge);
	    	      /* }
	    	   }catch(NumberFormatException e){
	    		   System.out.println("Number format exeption occured");
	    	   }
	    	   
	       }*/
	      
	       requestContext.abortWith(builder.build());

	    }
	    protected void checkOrigin(ContainerRequestContext requestContext, String origin) throws IOException
	    {
	       if (!allowedOrigins.contains("*") && !allowedOrigins.contains(origin))
	       {
	          requestContext.setProperty("cors.failure", true);
	          //throw new ForbiddenException(Messages.MESSAGES.originNotAllowed(origin));
	          throw new IOException("Origin not troper ");
	       }
	    }
	    private boolean isUserAllowed(final String username, final String password, final Set<String> rolesSet)
	    {
	        boolean isAllowed = false;
	         
	        //Step 1. Fetch password from database and match with password in argument
	        //If both match then get the defined role for user from database and continue; else return isAllowed [false]
	        //Access the database and do this part yourself
	        //String userRole = userMgr.getUserRole(username);
	        
	        if(username.equals("howtodoinjava") && password.equals("password"))
	        {
	        	String userRole = "ADMIN";
	            
	            //Step 2. Verify user role
	            if(rolesSet.contains(userRole))
	            {
	                isAllowed = true;
	            }
	        }
	        return isAllowed;
	    }
	}