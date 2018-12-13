using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.WindowsAzure.Storage.Blob;
using nClam;

namespace Blob.VirusScan
{
    //You will notice that I am providing bindings that are not used in this trigger.  This is just here for education and how to get other properties of the blob
    //Most exampls just show you the stream coming in.
    public static class VirusScan
    {
        [FunctionName("VirusScanTrigger")]
        public static async Task Run([BlobTrigger("staging/{name}")] Stream blob, string name, Uri uri,
            BlobProperties properties, IDictionary<string, string> metadata, TraceWriter log)
        {
            try
            {
                var clam = new ClamClient("localhost", 3310);
                var clamVersion = await clam.GetVersionAsync();

                //Make sure we can connect to the ClamAV Server
                var pingResult = await clam.PingAsync();

                if (!pingResult)
                {
                    throw new ApplicationException(
                        "The client failed to connect to the ClamAV Server.  Please check to see if the server is running and accessible on the configured port.");
                }

                //Dont exceed this value.  ClamAV server can be increased to 4GB, but you must have the resources available.
                var maxStreamSize = clam.MaxStreamSize;
                if (blob.Length > maxStreamSize)
                {
                    log.Info($"Blob {name} is too large to be scanned in memory.  Moving to deadletter container");
                    throw new InsufficientMemoryException(
                        $"Blob {name} is too large to be scanned in memory.  Moving to deadletter container");
                }

                //We are going to limit ourselves to block blobs, append blobs, and unspecified blobs.  
                var cloudBlob = new CloudBlob(uri);
                if (cloudBlob.BlobType == BlobType.PageBlob)
                {
                    throw new ApplicationException(
                        $"Blob {cloudBlob.Name} has an unsupported type. BlobType = {cloudBlob.BlobType.ToString()}");
                }

                var scanResult = await clam.SendAndScanFileAsync(blob);

                switch (scanResult.Result)
                {
                    case ClamScanResults.Clean:
                        //The blob is clean.  Move to production
                        log.Info($"Blob {name}. ScannResult = Clean, ClamVersion = {0}", clamVersion);
                        break;
                    case ClamScanResults.VirusDetected:
                        //Bad blob.  Move to quarantine.
                        log.Warning($"Blob {name} has a virus! Name = {0}", scanResult.InfectedFiles.First().VirusName);
                        break;
                    case ClamScanResults.Unknown:
                        //Unknown.  Moving to deadletter
                        log.Warning($"Blob {name} scan results unknown! Name = {0}",
                            scanResult.InfectedFiles.First().VirusName);
                        break;
                    case ClamScanResults.Error:
                        //Unknown.  Moving to deadletter
                        log.Warning($"Blob {name} has a virus! Name = {0}", scanResult.InfectedFiles.First().VirusName);
                        break;
                }

                log.Info($"C# Blob trigger function Processed blob\n Name:{name} \n Size: {blob.Length} Bytes");
            }
            catch (SocketException ex)
            {
                log.Error(ex.Message, ex);
            }
            catch (InsufficientMemoryException ex)
            {
                log.Error(ex.Message, ex);
                //Todo: Move to deadletter
            }
            catch (ApplicationException ex)
            {
                log.Error(ex.Message, ex);
            }
            catch (Exception ex)
            {

            }
        }

        public static string MoveBlob(string container, string blobName, Stream blobStream)
        {
            try
            {
                //Get MD5 Hash of Stream
                using (var md5Hash = MD5.Create())
                {
                    blobStream.Position = 0;
                    blobStream.Seek(0, SeekOrigin.Begin);
                    var sourceHash = ComputeMD5Hash(md5Hash, blobStream);

                    blobStream.Position = 0;
                    blobStream.Seek(0, SeekOrigin.Begin);

                    var blobContainer = _context.CloudBlobClient.GetContainerReference(container.ToLower());
                    blobContainer.CreateIfNotExists();

                    var blockBlob = blobContainer.GetBlockBlobReference(blobName);
                    blockBlob.UploadFromStream(blobStream);

                    return blockBlob.Properties.ContentMD5;
                }
            }
            catch (Exception ex)
            {
                throw;
            }
        }
    }
}
