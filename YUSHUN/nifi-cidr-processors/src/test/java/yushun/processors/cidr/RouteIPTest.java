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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.apache.nifi.util.TestRunner;
import org.apache.nifi.util.TestRunners;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.nifi.processor.Relationship;
import org.apache.nifi.util.MockFlowFile;


public class RouteIPTest {

    private TestRunner testRunner;

    @Before
    public void init() {
        testRunner = TestRunners.newTestRunner(RouteIP.class);
    }

    @Test
    public void testProcessor() {

    }
    
    @Test
    public void testParseCidrList() {
    	
    }
    
    @Test
    public void testRelationships() throws IOException {
        final TestRunner runner = TestRunners.newTestRunner(RouteIP.class);
        runner.setProperty(RouteIP.EXTRACT_STRATEGY, RouteIP.SATISFIES_EXPRESSION);
        runner.setProperty(RouteIP.IP_ADDR_EXPRESSION, "${tcp.sender}");
        runner.setProperty(RouteIP.CIDR_LIST, "10.2.1.0/24");

        runner.run();

        Set<Relationship> relationshipSet = runner.getProcessor().getRelationships();
        Set<String> expectedRelationships = new HashSet<>(Arrays.asList("matched", "unmatched", "original"));

        assertEquals(expectedRelationships.size(), relationshipSet.size());
        for (Relationship relationship : relationshipSet) {
            assertTrue(expectedRelationships.contains(relationship.getName()));
        }
    }
    
    @Test
    public void testInvalidCidrList() throws IOException {
        final TestRunner runner = TestRunners.newTestRunner(new RouteIP());
        runner.setProperty(RouteIP.EXTRACT_STRATEGY, RouteIP.SATISFIES_EXPRESSION);
        runner.setProperty(RouteIP.IP_ADDR_EXPRESSION, "${tcp.sender}");
        runner.setProperty(RouteIP.CIDR_LIST, "10.2.1.0/45");

        runner.assertNotValid();
    }

    @Test
    public void testInvalidExpression() throws IOException {
        final TestRunner runner = TestRunners.newTestRunner(new RouteIP());
        runner.setProperty(RouteIP.EXTRACT_STRATEGY, RouteIP.SATISFIES_EXPRESSION);
        runner.setProperty(RouteIP.IP_ADDR_EXPRESSION, "${tcp.sender");
        runner.setProperty(RouteIP.CIDR_LIST, "10.2.1.0/24");

        runner.assertNotValid();
    }

    @Test
    public void testValidExpression() throws IOException {
        final TestRunner runner = TestRunners.newTestRunner(new RouteIP());
        runner.setProperty(RouteIP.EXTRACT_STRATEGY, RouteIP.SATISFIES_EXPRESSION);
        runner.setProperty(RouteIP.IP_ADDR_EXPRESSION, "${tcp.sender}");
        runner.setProperty(RouteIP.CIDR_LIST, "10.2.1.0/24");

        runner.assertValid();
    }

    @Test
    public void testValidRegex() throws IOException {
        final TestRunner runner = TestRunners.newTestRunner(new RouteIP());
        runner.setProperty(RouteIP.EXTRACT_STRATEGY, RouteIP.MATCHES_REGULAR_EXPRESSION);
        runner.setProperty(RouteIP.IP_ADDR_REGEX, "^IP:(.*)");
        runner.setProperty(RouteIP.CIDR_LIST, "10.2.1.0/24");

        runner.assertValid();
    }

    @Test
    public void testInvalidRegex() throws IOException {
    	// There should be a captured group in the regex
        final TestRunner runner = TestRunners.newTestRunner(new RouteIP());
        runner.setProperty(RouteIP.EXTRACT_STRATEGY, RouteIP.MATCHES_REGULAR_EXPRESSION);
        runner.setProperty(RouteIP.IP_ADDR_REGEX, "^IP:.*");
        runner.setProperty(RouteIP.CIDR_LIST, "10.2.1.0/24");

        runner.assertNotValid();
    }

    @Test
    public void testRegexDispatchResult() throws IOException {
        final TestRunner runner = TestRunners.newTestRunner(new RouteIP());
        runner.setProperty(RouteIP.EXTRACT_STRATEGY, RouteIP.MATCHES_REGULAR_EXPRESSION);
        runner.setProperty(RouteIP.IP_ADDR_REGEX, "IP:(.*)");
        runner.setProperty(RouteIP.CIDR_LIST, "10.2.1.0/24");
        
        runner.enqueue("IP:10.2.1.15\nIP:10.2.2.2".getBytes("UTF-8"));
        runner.run();

        runner.assertTransferCount("matched", 1);
        runner.assertTransferCount("unmatched", 1);
        runner.assertTransferCount("original", 1);
        
        final MockFlowFile outMatched = runner.getFlowFilesForRelationship("matched").get(0);
        outMatched.assertContentEquals("IP:10.2.1.15\n".getBytes("UTF-8"));
        final MockFlowFile outUnmatched = runner.getFlowFilesForRelationship("unmatched").get(0);
        outUnmatched.assertContentEquals("IP:10.2.2.2".getBytes("UTF-8"));
        
    }
    
    @Test
    public void testExpressionDispatchSuccess() throws IOException {
        final TestRunner runner = TestRunners.newTestRunner(new RouteIP());
        runner.setProperty(RouteIP.EXTRACT_STRATEGY, RouteIP.SATISFIES_EXPRESSION);
        runner.setProperty(RouteIP.IP_ADDR_EXPRESSION, "${tcp.sender}");
        runner.setProperty(RouteIP.CIDR_LIST, "10.2.1.0/24");
        Map<String, String> attributes = new HashMap<>();
        attributes.put("tcp.sender", "10.2.1.15");
        runner.enqueue("log from ListenTcp processor\n".getBytes("UTF-8"), attributes);
        runner.run();

        runner.assertTransferCount("matched", 1);
        runner.assertTransferCount("unmatched", 0);
        runner.assertTransferCount("original", 1);
        
        final MockFlowFile outMatched = runner.getFlowFilesForRelationship("matched").get(0);
        outMatched.assertContentEquals("log from ListenTcp processor\n".getBytes("UTF-8"));
        
    }

    @Test
    public void testExpressionDispatchNoMatch() throws IOException {
        final TestRunner runner = TestRunners.newTestRunner(new RouteIP());
        runner.setProperty(RouteIP.EXTRACT_STRATEGY, RouteIP.SATISFIES_EXPRESSION);
        runner.setProperty(RouteIP.IP_ADDR_EXPRESSION, "${tcp.sender}");
        runner.setProperty(RouteIP.CIDR_LIST, "10.2.1.0/24");
        Map<String, String> attributes = new HashMap<>();
        attributes.put("tcp.sender", "10.2.2.15");
        runner.enqueue("log from ListenTcp processor\n".getBytes("UTF-8"), attributes);
        runner.run();

        runner.assertTransferCount("matched", 0);
        runner.assertTransferCount("unmatched", 1);
        runner.assertTransferCount("original", 1);
        
        final MockFlowFile outMatched = runner.getFlowFilesForRelationship("unmatched").get(0);
        outMatched.assertContentEquals("log from ListenTcp processor\n".getBytes("UTF-8"));
        
    }
    
    @Test
    public void testExpressionDispatchInvalidIp() throws IOException {
        final TestRunner runner = TestRunners.newTestRunner(new RouteIP());
        runner.setProperty(RouteIP.EXTRACT_STRATEGY, RouteIP.SATISFIES_EXPRESSION);
        runner.setProperty(RouteIP.IP_ADDR_EXPRESSION, "${tcp.sender}");
        runner.setProperty(RouteIP.CIDR_LIST, "10.2.1.0/24");
        Map<String, String> attributes = new HashMap<>();
        attributes.put("tcp.sender", "www.example.com");
        runner.enqueue("log from ListenTcp processor\n".getBytes("UTF-8"), attributes);
        runner.run();

        runner.assertTransferCount("matched", 0);
        runner.assertTransferCount("unmatched", 1);
        runner.assertTransferCount("original", 1);
        
        final MockFlowFile outMatched = runner.getFlowFilesForRelationship("unmatched").get(0);
        outMatched.assertContentEquals("log from ListenTcp processor\n".getBytes("UTF-8"));
        
    }
}
