using System;
using System.IO;
using UnityEngine;
using HarmonyLib;
using BepInEx;
using System.ComponentModel;
using System.Reflection;
using System.Text.RegularExpressions;
using UnityEngine.SocialPlatforms;
using UnityExplorer.Hooks;
using UnityExplorer.UI;
using Photon.Pun;
using UnityExplorer;

namespace GorillaScript.Main
{
    [BepInPlugin("com.gorillascript.a", "gorillascript", "1.0.0")]
    public class Loader : BaseUnityPlugin
    {
        public void FixedUpdate()
        {
            MainThing.Awake();
            if (!GameObject.Find("Loader") && GorillaLocomotion.Player.hasInstance)
            {
                GameObject Loader = new GameObject("Loader");
                Loader.AddComponent<MainThing>();
            }
        }
        [HarmonyLib.HarmonyPatch(typeof(ExplorerCore))]
        [HarmonyLib.HarmonyPatch("Log"/*, MethodType.Normal*/)]
        public class Log
        {
            private static bool Prefix()
            {
                return false;
            }
        }
    }

    [BepInPlugin(modGUID, modName, modVersion)]
    [Description(modVersion)]
    public class HarmonyPatch : BaseUnityPlugin
    {
        public void Awake()
        {
            Harmony harmony = new Harmony(modName);
            harmony.PatchAll(Assembly.GetExecutingAssembly());
        }
        private const string modGUID = "gorilla.script";
        private const string modName = "gorilla.script";
        public const string modVersion = "1.0.0";
    }
}
