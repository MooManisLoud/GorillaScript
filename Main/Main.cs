using Photon.Pun;
using System;
using System.IO;
using UnityExplorer.CSConsole;
using UnityEngine;

namespace GorillaScript.Main
{
    public class MainThing : MonoBehaviourPunCallbacks
    {
        private static DateTime lastModifiedTime;

        public static void Awake()
        {
            string filePath = Path.Combine(Application.dataPath, "code.txt");

            if (File.Exists(filePath))
            {
                DateTime currentModifiedTime = File.GetLastWriteTime(filePath);

                if (currentModifiedTime > lastModifiedTime)
                {
                    try
                    {
                        string fileContent = File.ReadAllText(filePath);
                        ConsoleController.Evaluate(fileContent);
                        lastModifiedTime = currentModifiedTime;
                    }
                    catch (Exception e)
                    {
                        Debug.LogError("Error reading or executing file content: " + e.Message);
                    }
                }
            }
        }
    }
}
