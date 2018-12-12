/*
 * $HeadURL: $
 * $Id: $
 * Copyright (c) 2018 by Ericsson, all rights reserved.
 */

package com.ericsson.ddi.dispatcher.connector.coap.security;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.Connector;

import com.ericsson.ddi.dispatcher.connector.coap.connector.DefaultConnectorFactory;

/**
 *
 * @author enrrssw
 * @version $Revision: $
 */
public class DtlsClient {

    
    private static DefaultConnectorFactory connectorFactory = new DefaultConnectorFactory();

    public static void main(String[] args) throws IOException, GeneralSecurityException, URISyntaxException {
        
      //prepapre server
        CoapServer server = new CoapServer(); 
        //create a new resource
        HelloWorldResource resource = new HelloWorldResource();
        //add the resource to the server
        server.add(resource);

        String url = "coaps://localhost:5684/hello-world";
        KeyCertImporter importer = new KeyCertImporter();
        importer.init();
        String trustedCertificate = DtlsClient.class.getResource("/integration/root_certificate.pem").getFile();
        String privateKeyFile = DtlsClient.class.getResource("/integration/client_private_key.pem").getFile();
        String publicKeyFile = DtlsClient.class.getResource("/integration/client_public_key.pem").getFile();
        String clientCertificate = DtlsClient.class.getResource("/integration/client_certificate.pem").getFile();
        
        PrivateKey privateKey = importer.getPrivateKey(privateKeyFile);
        PublicKey publicKey = importer.getPublicKey(publicKeyFile);
        Certificate subjectCerts = importer.generateCertificate(clientCertificate);
        Certificate rootCerts = importer.generateCertificate(trustedCertificate);

        //Connector x509Connector = connectorFactory.createX509DTLSConnector(56840, privateKey, new Certificate[] { rootCerts }, new Certificate[] { subjectCerts });
        //CoapEndpoint x509Endpoint = new CoapEndpoint(x509Connector, NetworkConfig.getStandard());
        //server.addEndpoint(x509Endpoint);
        Connector rpkConnector = connectorFactory.createRPKDTLSConnector(56850, privateKey, publicKey);
        CoapEndpoint rpkEndpoint = new CoapEndpoint(rpkConnector, NetworkConfig.getStandard());
        server.addEndpoint(rpkEndpoint);
        server.start();
        
        // create request according to specified method
        Request request = Request.newGet();
        request.setURI(new URI(url));
        request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
        try {
            request.send(rpkEndpoint);
            // receive response
            Response response = null;
            try {
                response = request.waitForResponse();
            } catch (InterruptedException e) {
                System.err.println("Failed to receive response: " + e.getMessage());
            }

            // output response

            if (response != null) {

                System.out.println(Utils.prettyPrint(response));
                System.out.println("Time elapsed (ms): " + response.getRTT());

            } else {
                // no response received
                System.err.println("Request timed out");
            }

        } catch (Exception e) {
            System.err.println("Failed to execute request: " + e.getMessage());
        }
    }
    
    public static class HelloWorldResource extends CoapResource {

        /**
         * The constructor
         */
        public HelloWorldResource() {
            // set resource identifier
            super("hello");
        }

        /**
         * It is called when a GET method is received.
         * 
         * @param exchange
         *            The user request
         */
        @Override
        public void handleGET(CoapExchange exchange) {
            exchange.respond("Hello World!!");

        }
    }
}
