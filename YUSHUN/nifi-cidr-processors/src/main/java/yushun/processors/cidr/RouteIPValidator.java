package yushun.processors.cidr;

import org.apache.nifi.processor.util.StandardValidators;

import org.apache.commons.net.util.SubnetUtils;
import org.apache.nifi.components.ValidationContext;
import org.apache.nifi.components.ValidationResult;
import org.apache.nifi.components.Validator;

public class RouteIPValidator extends StandardValidators {
    public static final Validator CIDR_COMMA_SEPERATED_LIST_VALIDATOR = new Validator() {
        @Override
        public ValidationResult validate(final String subject, final String value, final ValidationContext context) {
            String reason = null;
        	String[] parts = value.split(",");
        	if (parts.length == 0) {
        		reason = "an empty cidr list";
        	}
        	
        	for (int i = 0; i < parts.length; i++) {
        	    try {
        	        SubnetUtils subnet = new SubnetUtils(parts[i]);
        	    } catch (IllegalArgumentException e) {
        	        reason = "invalid cidr notation";
        	    }
        	}
        	
            return new ValidationResult.Builder().subject(subject).input(value).explanation(reason).valid(reason == null).build();
        }
    };
 }
