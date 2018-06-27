/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package yushun.processors.cidr;

import org.apache.commons.net.util.SubnetUtils;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.apache.nifi.components.AllowableValue;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.components.PropertyValue;
import org.apache.nifi.components.ValidationContext;
import org.apache.nifi.components.ValidationResult;
import org.apache.nifi.components.Validator;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.annotation.behavior.EventDriven;
import org.apache.nifi.annotation.behavior.InputRequirement;
import org.apache.nifi.annotation.behavior.SideEffectFree;
import org.apache.nifi.annotation.behavior.SupportsBatching;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.behavior.InputRequirement.Requirement;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.expression.AttributeExpression.ResultType;
import org.apache.nifi.logging.ComponentLog;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.io.InputStreamCallback;
import org.apache.nifi.processor.io.OutputStreamCallback;
import org.apache.nifi.processor.util.StandardValidators;
/*import org.apache.nifi.processors.standard.util.NLKBufferedReader;*/

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

@EventDriven
@SideEffectFree
@SupportsBatching
@InputRequirement(Requirement.INPUT_REQUIRED)
@Tags({"filter", "ipv4", "cidr"})
@CapabilityDescription("Routing flow contents by extracted ip v4 addresses agaist given cidrs")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
public class RouteIP extends AbstractProcessor {
	public static final String CIDR_DELIMITER = ",";
	public static final int CAPTURED_GROUP_NUMBER = 1;
	
	private static final String satisfiesExpression = "Satisfies Expression";
	private static final String matchesRegularExpressionValue = "Matches Regular Expression";
	
    public static final AllowableValue SATISFIES_EXPRESSION = new AllowableValue(satisfiesExpression, satisfiesExpression,
            "Extract ip address from an expression ");
    public static final AllowableValue MATCHES_REGULAR_EXPRESSION = new AllowableValue(matchesRegularExpressionValue, matchesRegularExpressionValue,
            "Extract ip address from capture group of regex");

	
    public static final PropertyDescriptor EXTRACT_STRATEGY = new PropertyDescriptor.Builder()
            .name("Extract Strategy")
            .description("Specifies how to extract ip addresses from each lines")
            .required(true)
            .allowableValues(SATISFIES_EXPRESSION, MATCHES_REGULAR_EXPRESSION)
            .dynamic(false)
            .build();
    
    public static final PropertyDescriptor IP_ADDR_EXPRESSION = new PropertyDescriptor
            .Builder().name("IP_ADDR_EXPRESSION")
            .displayName("IP Address Expression")
            .description("Expression to extract ip addresses to be filtered")
            .required(false)
            .expressionLanguageSupported(true)
            .addValidator(StandardValidators.createAttributeExpressionLanguageValidator(ResultType.STRING, false))
            .build();
    public static final PropertyDescriptor IP_ADDR_REGEX = new PropertyDescriptor.Builder()
            .name("Regular Expression")
            .description("Regular Expression to extract IP address from each line via the first captured group.")
            .addValidator(StandardValidators.createRegexValidator(1, 1, false))
            .expressionLanguageSupported(false)
            .required(false)
            .build();
    public static final PropertyDescriptor CIDR_LIST = new PropertyDescriptor
            .Builder().name("CIDR_LIST")
            .displayName("CIDR List")
            .description("Comma seperated cidr list to match")
            .required(true)
            .addValidator(RouteIPValidator.CIDR_COMMA_SEPERATED_LIST_VALIDATOR)
            .build();
    public static final PropertyDescriptor CHARACTER_SET = new PropertyDescriptor.Builder()
            .name("Character Set")
            .description("The Character Set in which the incoming text is encoded")
            .required(true)
            .addValidator(StandardValidators.CHARACTER_SET_VALIDATOR)
            .defaultValue("UTF-8")
            .build();

    public static final Relationship REL_ORIGINAL = new Relationship.Builder()
            .name("original")
            .description("The original input file will be routed to this destination when the lines have been successfully routed to 1 or more relationships")
            .build();
    public static final Relationship REL_NO_MATCH = new Relationship.Builder()
            .name("unmatched")
            .description("Data that does not matches the cidr will be routed to this relationship")
            .build();
    public static final Relationship REL_MATCH = new Relationship.Builder()
            .name("matched")
            .description("Data that matches one cidr will be routed to this relationship")
            .build();
    private List<PropertyDescriptor> descriptors;

    private Set<Relationship> relationships;
    private List<SubnetUtils> cidr_list;
    private volatile Pattern  matchingRegex = null;
    private volatile PropertyValue extractExpression = null;
    private InetAddressValidator ipValidator = new InetAddressValidator();
    
    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<PropertyDescriptor>();
        descriptors.add(IP_ADDR_EXPRESSION);
        descriptors.add(IP_ADDR_REGEX);
        descriptors.add(CIDR_LIST);
        descriptors.add(EXTRACT_STRATEGY);
        descriptors.add(CHARACTER_SET);
        this.descriptors = Collections.unmodifiableList(descriptors);

        final Set<Relationship> relationships = new HashSet<Relationship>();
        relationships.add(REL_ORIGINAL);
        relationships.add(REL_NO_MATCH);
        relationships.add(REL_MATCH);
        this.relationships = Collections.unmodifiableSet(relationships);
        
        this.cidr_list = new ArrayList<SubnetUtils>();
    }

    @Override
    public Set<Relationship> getRelationships() {
        return this.relationships;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return descriptors;
    }
    @Override
    protected Collection<ValidationResult> customValidate(ValidationContext validationContext) {
        Collection<ValidationResult> results = new ArrayList<>(super.customValidate(validationContext));
        boolean dynamicProperty = false;

        final String extractStrategy = validationContext.getProperty(EXTRACT_STRATEGY).getValue();
        final boolean compileRegex = extractStrategy.equals(matchesRegularExpressionValue);
        //final boolean requiresExpression = matchStrategy.equalsIgnoreCase(satisfiesExpression);

        Validator validator = StandardValidators.NON_EMPTY_VALIDATOR;
        ValidationResult validationResult;
        if (compileRegex) {
        	final String propValue = validationContext.getProperty(IP_ADDR_REGEX).getValue();
        	validationResult = validator.validate(IP_ADDR_REGEX.getName(), propValue, validationContext);
        } else {
        	final String propValue = validationContext.getProperty(IP_ADDR_EXPRESSION).getValue();
        	validationResult = validator.validate(IP_ADDR_EXPRESSION.getName(), propValue, validationContext);
        }
        if (validationResult != null) {
            results.add(validationResult);
        }
        return results;
    }

    @OnScheduled
    public void onScheduled(final ProcessContext context) {
    	final String c_list = context.getProperty(CIDR_LIST).getValue();
    	parseCidrList(c_list);
    	final String extractStrategy = context.getProperty(EXTRACT_STRATEGY).getValue();
    	if (extractStrategy.equals(matchesRegularExpressionValue)) {
    		final String regex = context.getProperty(IP_ADDR_REGEX).getValue();
    		if (regex != null) {
    			matchingRegex = Pattern.compile(regex);
    		}
    	} else {
    		extractExpression = context.getProperty(IP_ADDR_EXPRESSION);
    	}
    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
        FlowFile originalFlowFile = session.get();
        if ( originalFlowFile == null ) {
            return;
        }
        // TODO implement
        final ComponentLog logger = getLogger();
        final Charset charset = Charset.forName(context.getProperty(CHARACTER_SET).getValue());
        final String extractStrategy = context.getProperty(EXTRACT_STRATEGY).getValue();
        
        final boolean compileRegex = extractStrategy.equals(matchesRegularExpressionValue);
        final Map<Relationship, FlowFile> flowFileMap = new HashMap<>();
        
        session.read(originalFlowFile, new InputStreamCallback() {
            @Override
            public void process(final InputStream in) throws IOException {
                try (final Reader inReader = new InputStreamReader(in, charset);
                    final NLKBufferedReader reader = new NLKBufferedReader(inReader)) {

                    final Map<String, String> variables = new HashMap<>(2);

                    int lineCount = 0;
                    String line;
                    while ((line = reader.readLine()) != null) {

                        final String matchLine;
                        final String lineWithoutEndings;
                        final int indexOfCR = line.indexOf("\r");
                        final int indexOfNL = line.indexOf("\n");
                        if (indexOfCR > 0 && indexOfNL > 0) {
                            lineWithoutEndings = line.substring(0, Math.min(indexOfCR, indexOfNL));
                        } else if (indexOfCR > 0) {
                            lineWithoutEndings = line.substring(0, indexOfCR);
                        } else if (indexOfNL > 0) {
                            lineWithoutEndings = line.substring(0, indexOfNL);
                        } else {
                            lineWithoutEndings = line;
                        }

                        matchLine = lineWithoutEndings;
                        variables.put("line", line);
                        variables.put("lineNo", String.valueOf(++lineCount));
                        String ipAddress = extractLine(matchLine, compileRegex, originalFlowFile, variables);
                        if(ipAddress != null && ifIpMatchCIDR(ipAddress)) {
                        	appendLine(session, flowFileMap, REL_MATCH, originalFlowFile, line, charset);
                        } else {
                        	appendLine(session, flowFileMap, REL_NO_MATCH, originalFlowFile, line, charset);
                        }
                    }
                }
            }
        });
        
        for (final Map.Entry<Relationship, FlowFile> entry : flowFileMap.entrySet()) {
            final Relationship relationship = entry.getKey();
            final FlowFile flowFile = entry.getValue();
            logger.info("Created {} from {}; routing to relationship {}", new Object[] {flowFile, originalFlowFile, relationship.getName()});
            session.getProvenanceReporter().route(flowFile, entry.getKey());
            session.transfer(flowFile, entry.getKey());
        }

        logger.info("Routing {} to {}", new Object[] {originalFlowFile, REL_ORIGINAL});
        session.getProvenanceReporter().route(originalFlowFile, REL_ORIGINAL);
        session.transfer(originalFlowFile, REL_ORIGINAL);

    }
	
    private String extractLine(String line, boolean compileRegex, FlowFile flowFile, final Map<String, String> variables) {
    	String ipAddress = null;
    	if (compileRegex) {
    		Matcher matcher = matchingRegex.matcher(line);
    		if (matcher.matches()) {
    			ipAddress = matcher.group(CAPTURED_GROUP_NUMBER);
    		}    		 
    	} else {
    		ipAddress = extractExpression.evaluateAttributeExpressions(flowFile, variables).getValue();
    	}
    	return ipAddress;
    }
    
    private void appendLine(final ProcessSession session, final Map<Relationship, FlowFile> flowFileMap, final Relationship relationship,
            final FlowFile original, final String line, final Charset charset) {

            FlowFile flowFile = flowFileMap.get(relationship);
            if (flowFile == null) {
                flowFile = session.create(original);
            }

            flowFile = session.append(flowFile, new OutputStreamCallback() {
                @Override
                public void process(final OutputStream out) throws IOException {
                    out.write(line.getBytes(charset));
                }
            });

            flowFileMap.put(relationship, flowFile);
        }

    
    private boolean ifIpMatchCIDR(String ipaddr) {
		if (!ipValidator.isValidInet4Address(ipaddr)) {
			return false;
		}
		for(SubnetUtils subnet : this.cidr_list) {
			boolean matches = subnet.getInfo().isInRange(ipaddr);
			if (matches) {
				return true;
			}
		}
		return false;
	}
	
    private boolean parseCidrList(String cidrs) {
    	String[] parts = cidrs.split(",");
    	if (parts.length == 0) {
    		return false;
    	}
    	List<SubnetUtils> c_list = new ArrayList<SubnetUtils>();
    	for (int i = 0; i < parts.length; i++) {
    	    try {
    	        SubnetUtils subnet = new SubnetUtils(parts[i]);
    	        c_list.add(subnet);
    	    } catch (IllegalArgumentException e) {
    	        return false;
    	    }
    	}
    	this.cidr_list.addAll(c_list); 
    	return true;
    }
    

}

