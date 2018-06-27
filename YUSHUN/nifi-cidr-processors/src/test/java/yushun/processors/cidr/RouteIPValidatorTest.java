package yushun.processors.cidr;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import org.apache.nifi.components.ValidationContext;
import org.apache.nifi.components.ValidationResult;
import org.apache.nifi.components.Validator;
import org.junit.Test;


public class RouteIPValidatorTest {
    @Test
    public void testNonBlankValidator() {
        Validator val = RouteIPValidator.CIDR_COMMA_SEPERATED_LIST_VALIDATOR;
        ValidationContext vc = mock(ValidationContext.class);
        ValidationResult vr = val.validate("foo", "", vc);
        assertFalse(vr.isValid());
        vr = val.validate("foo", "this is not a cidr notation/45", vc);
        assertFalse(vr.isValid());

        vr = val.validate("foo", "10.2.3.0/45", vc);
        assertFalse(vr.isValid());
        
        vr = val.validate("foo", "10.2.700.0/45", vc);
        assertFalse(vr.isValid());
        
        vr = val.validate("foo", "10.2.0.0/24,10.2.0.0/28", vc);
        assertTrue(vr.isValid());
        
        vr = val.validate("foo", "10.2.0.15/32", vc);
        assertTrue(vr.isValid());
    }

}
