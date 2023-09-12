using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using System.Security.Cryptography;
using System.Text;

namespace TimestampGithubExample
{
    class TimeStampHelper
    {
        private string timeStampServerUrl { get; set; }
        private string credentialsBase64 { get; set; }

        public TimeStampHelper(string username, string password, string timeStampServerUrl)
        {
            this.timeStampServerUrl = timeStampServerUrl;

            this.credentialsBase64 = System.Convert.ToBase64String(Encoding.GetEncoding("UTF-8")
                            .GetBytes(username + ":" + password));
        }

        /**
         * Generates a TimeStampRequest including the given byte[]-data.
         */
        public TimeStampRequest generateRequest(byte[] data)
        {
            byte[] hash = SHA256.Create().ComputeHash(data);

            #region Generate a TimestampRequest from the read data

            TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
            reqGen.SetCertReq(true);

            TimeStampRequest tsReq = reqGen.Generate(TspAlgorithms.Sha256, hash, Org.BouncyCastle.Math.BigInteger.ValueOf(100));

            #endregion

            return tsReq;
        }
        
        /**
         * Generates a TimeStampRequest including the given string-data.
         */
        public TimeStampRequest generateRequest(string data)
        {
            byte[] dataAsBytes = Encoding.UTF8.GetBytes(data);
            return generateRequest(dataAsBytes);
        }

        /**
         * Sends the given tsRequest per HTTP to the configured TimeStampServer and returns the response.
         */
        public TimeStampResponse sendRequest(TimeStampRequest tsRequest)
        {
            byte[] tsRequestBytes = tsRequest.GetEncoded();

            #region Prepare the request

            HttpClient client = new HttpClient();
            client.BaseAddress = new Uri(timeStampServerUrl);
            client.DefaultRequestHeaders.Add("Authorization", $"Basic {credentialsBase64}");

            ByteArrayContent content = new ByteArrayContent(tsRequestBytes);
            content.Headers.Add("Content-Type", "application/timestamp-query");

            #endregion

            #region Send the request

            HttpResponseMessage responseMsg = client.PostAsync("timestamp", content).Result;

            if (!responseMsg.IsSuccessStatusCode)
            {
                Console.WriteLine($"Request failed (Code: {responseMsg.StatusCode})");
                return null;
            }

            byte[] responseContent = responseMsg.Content.ReadAsByteArrayAsync().Result;

            TimeStampResponse tsResponse = new TimeStampResponse(responseContent);

            #endregion

            return tsResponse;
        }

        /**
         * Validates the TimeStampRequest
         */
        public bool Validate(TimeStampResponse tsResponse, TimeStampRequest tsRequest, byte[] timeStampTestCertificate)
        {
            try
            {
                tsResponse.Validate(tsRequest);

                if (timeStampTestCertificate == null)
                {
                    Console.WriteLine("The provided certificate with which part of the verification would be done, is null");
                    return false;
                }

                var tsToken = tsResponse.TimeStampToken;
                var timestamp = tsToken.TimeStampInfo.GenTime;


                tsToken.Validate(new X509Certificate(timeStampTestCertificate));

                Console.WriteLine($"Your message was successfully timestamped at: {timestamp}");

                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("The timestamp could not be successfully verified.\n");
                Console.WriteLine("Message: " + e.Message);
                return false;
            }
        }
    }
}