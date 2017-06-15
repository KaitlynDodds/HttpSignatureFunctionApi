using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;

namespace HttpSignatureFunctionApi
{
    public static class Verify
    {
        [FunctionName("HttpTriggerCSharp")]
        public static async Task<HttpResponseMessage> Run([HttpTrigger(AuthorizationLevel.Function, "post", Route = null)]HttpRequestMessage req, TraceWriter log)
        {
            log.Info("C# HTTP trigger function processed a request.");

            // Step 1) Check that HTTPRequest Message contains Authorization header 
                // auth-scheme is 'Signature'
                // auth-param includes keyId algorithm headers signature (all required in this case)

                // send 401 Unauthorized if Request does not contain necessary headers + info
                    // specify which headers are expected in WW-Authenticate header 
             
            // Step 2) Verify Signature 

                // a) Parse HttpResponseMessage to generate a Request object 

                // b) Parse Authorization header  
                    // keyId
                    // algorithm
                    // Signature (encoded value) 

                // c) Create new Signature object with keyId, algorithm and Request object
                   
                // d) Create new Signer object with Signature object

                // e) Call signer.Verify() given the encoded signature you received in the original HTTP request 
                
        }
    }
}