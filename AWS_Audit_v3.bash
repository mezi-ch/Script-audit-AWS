# !/bin/bash 

echo "##############################################################" | tee -a ./aws_audit.txt
echo "#  SCRIPT AUDIT Amazon AWS v3    - 15.12.2021 - Simon VANONY #" | tee -a ./aws_audit.txt
echo "##############################################################" | tee -a ./aws_audit.txt
echo "#    CIS Amazon Web Services Foundations Benchmark v 1.3.0.  #" | tee -a ./aws_audit.txt
echo "##############################################################" | tee -a ./aws_audit.txt

echo "[*] Quel est le nom de la région à auditer (ex : eu-west-3) ? \n"
read regionaudit

echo "[*] Creation de fichiers temporaires..."
touch ./tempaudit.txt
sleep 1
chmod 774 ./tempaudit.txt

echo "[*] Collecte des infos de AWS"
echo "###########################################################" | tee -a ./aws_audit.txt
echo "#           1 Identity and Access Management              #" | tee -a ./aws_audit.txt
echo "###########################################################" | tee -a ./aws_audit.txt

#Vérification que  tous les acces aux clés associees avec le compte root sont supprimees
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 1.4 Ensure no root user account access key exists" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
aws iam get-account-summary | grep AccountAccessKeysPresent | tee -a ./aws_audit.txt
echo "[*] Check 1.4 : If no root access keys exist the output will show \"AccountAccessKeysPresent\": 0" >> ./aws_audit.txt

#Verification que le MFA est actif pour root		
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 1.5 Ensure MFA is enabled for the "root user" account" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
aws iam get-account-summary | grep AccountMFAEnabled | tee -a ./aws_audit.txt
echo "[*] Check 1.5 : Ensure the AccountMFAEnabled property is set to 1." >> ./aws_audit.txt

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 1.6 Ensure hardware MFA is enabled for the 'root user' account" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[*] Etape 1" | tee -a ./aws_audit.txt
aws iam get-account-summary | grep AccountMFAEnabled | tee -a ./aws_audit.txt
echo "[*] Etape 2" | tee -a ./aws_audit.txt
aws iam list-virtual-mfa-devices | tee -a ./aws_audit.txt
echo "[*] Check 1.6 : The AccountMFAEnabled property is set to 1 will ensure that the root user account has MFA (Virtual or Hardware) Enabled." >> ./aws_audit.txt

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 1.7 Eliminate use of the root user for administrative and daily tasks" | tee -a ./aws_audit.txt
echo "[+] 1.10 Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password" | tee -a ./aws_audit.txt
echo "[+] 1.11 Do not setup access keys during initial user setup for all IAM users that have a console password" | tee -a ./aws_audit.txt
echo "[+] 1.12 Ensure credentials unused for 90 days or greater are disabled" | tee -a ./aws_audit.txt
echo "[+] 1.14 Ensure access keys are rotated every 90 days or less" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
aws iam generate-credential-report | tee -a ./aws_audit.txt
sleep 3
aws iam get-credential-report | tee -a ./aws_audit.txt
echo "[*] Check 1.7 : Must be base 64 decoded. Review password_last_used, access_key_1_last_used_date, access_key_2_last_used_date to determine when the root user was last used." >> ./aws_audit.txt
echo "[*] Check 1.10 : For any column having password_enabled set to true , ensure mfa_active is also set to true." >> ./aws_audit.txt
echo "[*] Check 1.11 : For any user having password_enabled set to true AND access_key_last_used_date set to N/A refer to the remediation to delete access keys." >> ./aws_audit.txt
echo "[*] Check 1.12 : Refer to CIS benchmark 1.3.0" >> ./aws_audit.txt
echo "[*] Check 1.14 : The access_key_1_last_rotated field in this file notes The date and time, in ISO 8601 date-time format, when the user's access key was created or last changed. If the user does not have an active access key, the value in this field is N/A (not applicable)." >> ./aws_audit.txt

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 1.8 Ensure IAM password policy requires minimum length of 14 or greater" | tee -a ./aws_audit.txt
echo "[+] 1.9 Ensure IAM password policy prevents password reuse" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
aws iam get-account-password-policy | tee -a ./aws_audit.txt
echo "Check 1.8 : Ensure the output of the above command includes \"MinimumPasswordLength\": 14 (or higher)" >> ./aws_audit.txt
echo "check 1.9 : Ensure the output of the above command includes \"PasswordReusePrevention\": 24" >> ./aws_audit.txt

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 1.13 Ensure there is only one active access key available for any single IAM user" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
#aws iam list-users --query "Users[*].UserName" > ./tempaudit.txt
aws iam list-users | grep UserName | cut -d ":" -f 2 | tr -d "[:blank:]" | tr -d "\"" | tr -d "," > ./tempaudit.txt
sleep 2
while read user ; do echo $user ; aws iam list-access-keys --user-name $user ; done < ./tempaudit.txt >> ./aws_audit.txt
echo "Check 1.13 : If the Status property value for more than one IAM access key is set to Active, the user access configuration is a finding." >> ./aws_audit.txt

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 1.15 Ensure IAM Users Receive Permissions Only Through Groups" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[*] Check for user attached policies" | tee -a ./aws_audit.txt
while read user ; do echo $user ; aws iam list-attached-user-policies --user-name $user ; done <./tempaudit.txt >> ./aws_audit.txt
echo "[*] Check for user policies" | tee -a ./aws_audit.txt
while read user ; do echo ^$user ; aws iam list-user-policies --user-name $user ; done < ./tempaudit.txt >> ./aws_audit.txt
echo "Check 1.15 : If any policies are returned, the user has an inline policy or direct policy attachment." >> ./aws_audit.txt

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 1.16 Ensure IAM policies that allow full "*:*" administrative privileges are not attached" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[*] Recuperation des Arn des policies et stockage en table..."
aws iam list-policies --only-attached | grep Arn | cut -d "\"" -f 4 > ./tempaudit.txt

declare -A policytab

i=1
while read item ; do 
	policytab[$i]=$item
	((i++))
done < ./tempaudit.txt

echo "[*] Recuperation des versions des policies et stockage en table..."
aws iam list-policies --only-attached | grep DefaultVersionId | cut -d "\"" -f 4 > ./tempaudit.txt

i=1
for key in "${!policytab[@]}"; do
	policytab[$key]=${policytab[$key]},$(head -n $i ./tempaudit.txt | tail -1)
	((i++))
done
echo "[*] Preparation pour l'interrogation finale des policies..." 
for key in "${!policytab[@]}"; do
	tempParentValue=${policytab[$key]}
	tempChildValue1=$(echo "$tempParentValue" | cut -d "," -f 1)
	tempChildValue2=$(echo "$tempParentValue" | cut -d "," -f 2)
	echo "[*] Recuperation de la policy avec arn $tempChildValue1 et version $tempChildValue2"
	echo "---${policytab[$key]}---" >> ./aws_audit.txt
	aws iam get-policy-version --policy-arn $tempChildValue1 --version-id $tempChildValue2 >> ./aws_audit.txt
done
echo "Check 1.16 : Checker manuellement des policies pour le moment " >> ./aws_audit.txt

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 1.17 Ensure a support role has been created to manage incidents with AWS Support" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[*] Interrogation des policies AWSSupportAccess..." | tee -a ./aws_audit.txt
aws iam list-policies --query "Policies[?PolicyName == 'AWSSupportAccess']"  | tee -a ./aws_audit.txt
echo "[*] Verification des entites..." | tee -a ./aws_audit.txt
aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess | tee -a ./aws_audit.txt
echo "Check 1.17 : In Output, Ensure PolicyRoles does not return empty. \"Example: Example: PolicyRoles: [ ]\" " >> ./aws_audit.txt

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 1.19 Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
aws iam list-server-certificates | tee -a ./aws_audit.txt
echo "Check 1.19 : Verify the ServerCertificateName and Expiration parameter value (expiration date) for each SSL/TLS certificate returned by the list-server-certificates command and determine if there are any expired server certificates currently stored in AWS IAM" >> ./aws_audit.txt

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 1.20 Ensure that S3 Buckets are configured with \"Block public access (bucket settings)\"" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
aws s3 ls | tee -a ./aws_audit.txt
aws s3 ls | cut -d " " -f 3 > ./tempaudit.txt
while read item ; do echo $item ; aws s3api get-public-access-block --bucket $item ; done < ./tempaudit.txt >> ./aws_audit.txt 
echo "Check 1.20 : If the output reads false for the separate configuration settings then proceed to the remediation." >> ./aws_audit.txt

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 1.21 Ensure that IAM Access analyzer is enabled" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
#Pas de retour correct a de fortes chances d'indiquer qu'aucun analyzer n'est créé
echo "[*] Verifie la presence d'analyseurs..." | tee -a ./aws_audit.txt
aws accessanalyzer list-analyzers | tee -a ./aws_audit.txt
echo "Check 1.21 : Ensure that the \"status\" is set to \"ACTIVE\"" >> ./aws_audit.txt

echo "###########################################################" | tee -a ./aws_audit.txt
echo "#                        2 Storage                        #" | tee -a ./aws_audit.txt
echo "###########################################################" | tee -a ./aws_audit.txt
echo "[+] 2.1 Simple Storage Service (S3)" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 2.1.1 Ensure all S3 buckets employ encryption-at-rest" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
while read item ; do echo $item ; aws s3api get-bucket-encryption --bucket $item ; done < tempaudit.txt >> ./aws_audit.txt
echo "Check 2.1.1 : Ensure that \"SSEAlgorithm\" is \"aws:kms\" or \"AES256\"" >> ./aws_audit.txt

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 2.1.2 Ensure S3 Bucket Policy allows HTTPS requests" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
while read item ; do echo $item ; aws s3api get-bucket-policy --bucket $item ; done < tempaudit.txt >> ./aws_audit.txt
echo "Check 2.1.2 : Confirm that aws:SecureTransport is set to false aws:SecureTransport:false and Confirm that the policy line has Effect set to Deny \"Effect:Deny\"" >> ./aws_audit.txt

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 2.2 Elastic Compute Cloud (EC2)" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 2.2.1 Ensure EBS volume encryption is enabled" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
aws --region $regionaudit ec2 get-ebs-encryption-by-default | tee -a ./aws_audit.txt
echo "Check 2.2.1 : Verify that \"EbsEncryptionByDefault\": true is displayed." >> ./aws_audit.txt

echo "###########################################################" | tee -a ./aws_audit.txt
echo "#                         3 Logging                       #" | tee -a ./aws_audit.txt
echo "###########################################################" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 3.5 Ensure AWS Config is enabled in all regions" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
aws configservice describe-configuration-recorders | tee - a ./aws_audit.txt
echo "Check 3.5 : Evaluate the output to ensure that there's at least one recorder for which recordingGroup object includes \"allSupported\": true AND \"includeGlobalResourceTypes\": true" >> ./aws_audit.txt 

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 3.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[*] Enumeration des buckets de logs..."  | tee - a ./aws_audit.txt
aws cloudtrail describe-trails --query 'trailList[*].S3BucketName' | grep -v "\[" | grep -v "\]" | tr -d "[:blank:]" | tr -d "\"" > ./tempaudit.txt
echo "[*] Analyse des buckets...."  | tee - a ./aws_audit.txt
while read item ; do echo $item ; aws s3api get-bucket-logging --bucket $item ; done < ./tempaudit.txt >> ./aws_audit.txt
echo "Check 3.6 : Ensure command does not returns empty output." >> ./aws_audit.txt

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 3.8 Ensure rotation for customer created CMKs is enabled" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[*] Liste des cles" | tee - a ./aws_audit.txt
aws kms list-keys | tee - a ./aws_audit.txt
echo "[*] Proprietes des cles" | tee - a ./aws_audit.txt
aws kms list-keys | grep KeyId | cut -d ":" -f 2 | tr -d "[:blank:]" | tr -d "\"" > ./tempaudit.txt
while read item ; do echo $item ; aws kms get-key-rotation-status --key-id $item ; done <./tempaudit.txt >> ./aws_audit.txt
echo "Check 3.8 : Ensure KeyRotationEnabled is set to true" >> ./aws_audit.txt 

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 3.1 Ensure CloudTrail is enabled in all regions"  | tee -a ./aws_audit.txt
echo "[+] 3.2 Ensure CloudTrail log file validation is enabled" | tee -a ./aws_audit.txt
echo "[+] 3.4 Ensure CloudTrail trails are integrated with CloudWatch Logs" | tee -a ./aws_audit.txt
echo "[+] 3.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[*] Enumeration des journaux..." | tee -a ./aws_audit.txt
aws cloudtrail describe-trails | tee -a ./aws_audit.txt
aws cloudtrail describe-trails | grep "\"Name\":" | cut -d ":" -f 2 | tr -d "[:blank:]" | tr -d "," | tr -d "\"" > ./tempaudit.txt
echo "[*] Interrogation des configs... Check 3.1 : MultiregionTrail - True" | tee -a ./aws_audit.txt
while read journaux ; echo $journaux ; do aws cloudtrail get-trail-status --name $journaux ; done < ./tempaudit.txt >> ./aws_audit.txt 
echo "[*] Interrogation des configs... Check 3.1 : IsLogging - True" | tee -a ./aws_audit.txt
while read journaux ; do echo $journaux ; aws cloudtrail get-trail-status --trail-name $journaux ; done < ./tempaudit.txt >> ./aws_audit.txt
echo "[*] Interrogation des configs... Check 3.1 : IncludeManagementEvents - True and ReadWriteType - All" | tee -a ./aws_audit.txt
while read journaux ; do echo $journaux ; aws cloudtrail get-event-selectors --trail-name $journaux ; done < ./tempaudit.txt >> ./aws_audit.txt
echo "Check 3.2 : Ensure LogFileValidationEnabled is set to true for each trail" >> ./aws_audit.txt
echo "Check 3.4 : Ensure CloudWatchLogsLogGroupArn is not empty and note the value of the Name property. Then Ensure the LatestcloudwatchLogdDeliveryTime property is set to a recent (~one day old) timestamp" >> ./aws_audit.txt
echo "Check 3.7 : For each trail listed, SSE-KMS is enabled if the trail has a \"KmsKeyId\" property defined." >> ./aws_audit.txt

echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[+] 3.10 Ensure that Object-level logging for write events is enabled for S3 bucket" | tee -a ./aws_audit.txt
echo "[+] 3.11 Ensure that Object-level logging for read events is enabled for S3 bucket" | tee -a ./aws_audit.txt
echo "-----------------------------------------------------------" | tee -a ./aws_audit.txt
echo "[*] Enumeration des journaux..."
aws cloudtrail list-trails --region $regionaudit --query Trails[*].Name | grep -v "\[" | grep -v "\]" | tr -d "[:blank:]" | tr -d "\"" > ./tempaudit.txt
echo "[*] Analyse des configurations..."
while read journaux ; do echo $journaux ; aws cloudtrail get-event-selectors --region $regionaudit --trail-name $journaux --query EventSelectors[*].DataResources[] ; done < ./tempaudit.txt
echo "Check 3.10 : If the get-event-selectors command returns an empty array '[]', the Data events are not included into the selected AWS Cloudtrail trail logging configuration, therefore the S3 object-level API operations performed within your AWS account are not recorded." >> ./aws_audit.txt
echo "Check 3.11 : If the get-event-selectors command returns an empty array, the Data events are not included into the selected AWS Cloudtrail trail logging configuration, therefore the S3 object-level API operations performed within your AWS account are not recorded." >> ./aws_audit.txt 

echo "[+] Fin du script Nettoyage des fichiers temporaires..."
#at the end : 
sleep 2
rm ./tempaudit.txt
echo "[!] Merci de renvoyer le fichier aws_audit.txt a l'auditeur."
