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

namespace HttpSignatureFunctionApi
{
    public static class Verify
    {

        [FunctionName("HttpTriggerCSharp")]
        public static async Task<HttpResponseMessage> Run([HttpTrigger(AuthorizationLevel.Function, "post", Route = null)]HttpRequestMessage req, TraceWriter log)
        {
            log.Info("HttpTriggerCSharp processed request");

            // Step 1) Check that HTTPRequest Message contains Authorization header 
            if (req.Headers.Authorization == null || Parser.IsValidAuthenticationHeader(req.Headers.Authorization))
            {
                log.Info("Request object did not contain valid Authorization header.");
                // return 401 Unauthorized
                return Send401Response("Authorization Attempt Failed, Invalid Signature");
            }

            // Step 2) Verify Signature 
            Signature signature = Signature.FromHttpRequest(req);
            string originalRequestSignature = signature.EncodedSignature;

            // d) Create new Signer object with Signature object
            Signer signer = new Signer(signature);

            // e) Call signer.Verify() given the encoded signature you received in the original HTTP request 
            if (signer.Verify(originalRequestSignature))
            {
                log.Info("Signature verification passed.");
                // if true, signatures match, send back 200 OK
                return Send200Response("Signature Verification Succesfull");
            }
            else
            {
                log.Info("Signature verification failed.");
                log.Info(String.Format("{0} : {1}", originalRequestSignature, signature.EncodedSignature));
                // if false, signatures did not match, send back error (401?)
                return Send401Response("Authorization Attempt Failed, Signature Verification Failed");
            }

        }

        private static HttpResponseMessage Send401Response(string message)
        {
            // send 401 Unauthorized if Request does not contain necessary headers + info
            HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            response.ReasonPhrase = message;
            response.Content = new StringContent("{\"active\":\"false\"}", System.Text.Encoding.UTF8, "application/json");

            // specify which headers are expected in WW-Authenticate header 
            response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Signature", "headers=\"(request-target) date digest\""));
            return response;
        }

        private static HttpResponseMessage Send200Response(string message)
        {
            HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.OK);
            response.ReasonPhrase = message;
            // indicate that verification has been successful in response content (as JSON object w/ active var)
            response.Content = new StringContent("{\"active\":\"true\"}", System.Text.Encoding.UTF8, "application/json");

            return response;
        }
    }
}