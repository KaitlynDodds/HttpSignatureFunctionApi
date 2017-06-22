using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;
using System.Net.Http.Headers;
using http.signature;
using System;
using System.Collections.Generic;
using http.signature.Exceptions;

namespace HttpSignatureFunctionApi
{
    public static class Verify
    {
        public static TraceWriter logger; 

        [FunctionName("HttpSignatureVerificationWorker")]
        public static async Task<HttpResponseMessage> Run([HttpTrigger(AuthorizationLevel.Function, "post", Route = "HttpSignature/verify")]HttpRequestMessage req, TraceWriter log)
        {
            logger = log;
            
            logger.Info("HttpSignatureVerificaion processed request");

            // Step 1) Check that HTTPRequest Message contains Authorization header 
            if (req.Headers.Authorization == null)
            {
                logger.Info("Request object did not contain an Authorization Header");
                return Send401Response("Authorization Attempt Failed, No Authorization Header");
            }

            try
            {
                // Step 2) Verify Signature 
                Signature signature = Signature.FromHttpRequest(req);
                logger.Info("Created signature from Http request");
                string originalRequestSignature = signature.EncodedSignature;
                logger.Info($"Request signature passed into function: {originalRequestSignature}");

                // Create new Signer object with Signature object
                Signer signer = new Signer(signature);
                logger.Info("Created signer instance with signature");

                // Call signer.Verify() given the encoded signature you received in the original HTTP request 
                logger.Info("Calling verify on signer");
                if (signer.Verify(originalRequestSignature))
                {
                    logger.Info($"Signature verification passed: {signature.EncodedSignature}");
                    return Send200Response("Signature Verification Succesfull");
                }
                else
                {
                    logger.Info($"Signature verification failed: {signature.EncodedSignature}");
                    return Send401Response("Authorization Attempt Failed, Signature Verification Failed");
                }
            }
            catch (InvalidSignatureString ex)
            {
                logger.Error("Invalid Signature String", ex);
                return Send401Response("Signature string could not be used, was invalid");
            }
            catch (InvalidAuthorizationHeader ex)
            {
                logger.Error("Invalid Authorization Header", ex);
                return Send401Response("Invalid Authorization Header");
            }
            catch (Exception ex)
            {
                logger.Error("Error Occured", ex);
                return Send401Response("Error Occured");
            }
            
            
        }

        private static HttpResponseMessage Send401Response(string message)
        {
            // send 401 Unauthorized if Request does not contain necessary headers + info
            HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            response.ReasonPhrase = message;

            // indicate that varification failed in response content (as JSON object w/ value 'verified')
            response.Content = new StringContent("{\"verified\":\"false\"}", System.Text.Encoding.UTF8, "application/json");
            logger.Info("Setting response content - {verified: false}");

            // specify which headers are expected in WWW-Authenticate header 
            response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Signature", "headers=\"date digest\""));
            logger.Info("Setting WWW-Authenticate header");

            logger.Info("Sending 401 Response");
            return response;
        }

        private static HttpResponseMessage Send200Response(string message)
        {
            // send back 200 if all went well
            HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.OK);
            response.ReasonPhrase = message;

            // indicate that verification has been successful in response content (as JSON object w/ value 'verified')
            response.Content = new StringContent("{\"verified\":\"true\"}", System.Text.Encoding.UTF8, "application/json");
            logger.Info("Setting response content - {verified: true}");

            logger.Info("Sending 200 Response");
            return response;
        }
    }
}