# AWS Identity Governance: Enforcing Delegated Administration via Permissions Boundaries

## **Project Overview**
In a scaling enterprise, centralizing all IAM tasks creates a bottleneck. However, delegating IAM privileges to junior administrators often leads to **Privilege Escalation** risks. 

This project demonstrates a high-governance solution using **AWS IAM Permissions Boundaries** and **Policy Conditions**. I engineered a "Delegated Admin" environment where a Junior Administrator can manage users and roles, but is mathematically restricted from escalating their own privileges or creating unauthorized Administrator accounts.

## **The Architecture (GRC Logic)**
The solution relies on a three-tier enforcement strategy:
1. **The Global Boundary (The Ceiling):** A Permissions Boundary that defines the absolute maximum power any delegated identity can possess.
2. **The Identity Policy (The Engine):** A least-privilege policy allowing specific IAM actions.
3. **The Condition Trap:** A logic gate that prevents user/role creation unless the specific Global Boundary is attached to the new entity.

---

## **Compliance Mapping & Framework Alignment**
This implementation directly enforces controls from global cybersecurity frameworks, translating regulatory language into technical guardrails.

| Framework | Control ID | Control Name | Technical Implementation in this Project |
| :--- | :--- | :--- | :--- |
| **NIST 800-53** | **AC-02** | Account Management | Automated enforcement of account creation constraints using IAM Condition Keys. |
| **NIST 800-53** | **AC-06** | Least Privilege | Use of Permissions Boundaries to set a "Maximum Allowable Power" ceiling that overrides identity-based allows. |
| **ISO 27001:2022** | **A.5.18** | Access Rights | Controlled delegation of access right provisioning, ensuring no single user can grant unauthorized elevated access. |
| **ISO 27001:2022** | **A.8.2** | Privileged Access Rights | Restricting the allocation of "AdministratorAccess" through explicit denies within the boundary policy. |
| **NDPR (Nigeria)** | **Part 2.1** | Data Governance | Strengthening the "Data Controller" environment by ensuring only governed identities can access systems processing citizen data. |

---

## **Key Technical Features**
* **Automated Compliance:** Used `iam:PermissionsBoundary` condition keys to enforce mandatory guardrail attachment at the moment of creation.
* **Privilege Escalation Neutralization:** Explicitly denied `iam:AttachUserPolicy` for the `AdministratorAccess` ARN within the boundary.
* **Self-Service Governance:** Implemented scoped MFA and Password management using AWS Policy Variables (`${aws:username}`).

## **Proof of Enforcement**

### 1. Mandatory Guardrail Enforcement
Below is an attempt by the Junior Admin to create a user *without* attaching the required Permissions Boundary. The request is denied by the **Condition Trap** in the identity policy. [Access Denied - Missing Boundary](Screenshots/User_Creation_Without_Permissions_Boundary_Denied.png)

### 2. Privilege Escalation Blocked
In this scenario, the Junior Admin successfully initiated user creation but attempted to attach the `AdministratorAccess` policy. While the user was created, the boundary triggered an **Explicit Deny** on the policy attachment, effectively neutering the account. [Successful Creation - Blocked Admin](Screenshots/Successful_User_Creation_Blocking_Privilege_Escalation.png)

---

## 📄 Policy Configurations

### A. Global-GRC-Boundary
This policy defines the absolute maximum permissions any delegated user or role can ever exercise. Even if an identity policy says "Allow All," this boundary acts as a filter.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowAllExceptGuardrails",
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        },
        {
            "Sid": "RestrictPassRoleToServicesOnly",
            "Effect": "Deny",
            "Action": "iam:PassRole",
            "Resource": "*",
            "Condition": {
                "StringNotLike": {
                    "iam:PassedToService": [
                        "ec2.amazonaws.com",
                        "lambda.amazonaws.com",
                        "rds.amazonaws.com",
                        "s3.amazonaws.com"
                    ]
                }
            }
        },
        {
            "Sid": "GRCGuardrailDenyAdminPolicy",
            "Effect": "Deny",
            "Action": [
                "iam:Attach*"
            ],
            "Resource": "*",
            "Condition": {
                "ArnEquals": {
                    "iam:PolicyARN": "arn:aws:iam::aws:policy/AdministratorAccess"
                }
            }
        },
        {
            "Sid": "GRCGuardrailProtectTheBoundary",
            "Effect": "Deny",
            "Action": [
                "iam:DeleteUserPermissionsBoundary",
                "iam:DeleteRolePermissionsBoundary",
                "iam:PutUserPermissionsBoundary",
                "iam:PutRolePermissionsBoundary",
                "iam:DeletePolicy",
                "iam:CreatePolicyVersion",
                "iam:SetDefaultPolicyVersion"
            ],
            "Resource": [
                "arn:aws:iam::*:user/Junior-IAM-Admin",
                "arn:aws:iam::*:policy/Global-GRC-Boundary"
            ]
        }
    ]
}
```

Logic Summary:
1. **AllowAllExceptGuardrails:** Sets the default posture to "Allow," ensuring the boundary doesn't block legitimate non-IAM service usage (S3, EC2, etc.).
2. **RestrictPassRoleToServicesOnly:** A critical security guardrail. It prevents the user from "passing" a powerful role to a malicious or unintended resource, restricting it only to verified AWS services.
3. **GRCGuardrailDenyAdminPolicy:** The Anti-Escalation block. It explicitly denies the attachment of the `AdministratorAccess` policy to anyone, effectively neutralizing the most common path to unauthorized root-access.
4. **GRCGuardrailProtectTheBoundary:** The Self-Preservation block. It prevents the Junior Admin from deleting or modifying the very boundary that restricts them, and protects the Global-GRC-Boundary policy from being tampered with.



### B. Junior-IAM-Admin-Permissions
This is the identity-based policy that grants the Junior Admin their functional powers, while baking in mandatory compliance checks.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowIAMManagementWithBoundary",
            "Effect": "Allow",
            "Action": [
                "iam:CreateRole",
                "iam:CreateUser",
                "iam:AttachRolePolicy",
                "iam:AttachUserPolicy",
                "iam:PutRolePermissionsBoundary",
                "iam:PutUserPermissionsBoundary"
            ],
            "Resource": "*",
            "Condition": {
                "ArnEquals": {
                    "iam:PermissionsBoundary": "arn:aws:iam::706059253302:policy/Global-GRC-Boundary"
                }
            }
        },
        {
            "Sid": "AllowCreateLoginProfile",
            "Effect": "Allow",
            "Action": "iam:CreateLoginProfile",
            "Resource": "*"
        },
        {
            "Sid": "AllowSelfServiceAndRead",
            "Effect": "Allow",
            "Action": [
                "iam:ChangePassword",
                "iam:CreateVirtualMFADevice",
                "iam:EnableMFADevice",
                "iam:List*",
                "iam:Get*",
                "iam:ResyncMFADevice"
            ],
            "Resource": "*"
        }
    ]
}
```

Logic Summary:
1. **AllowIAMManagementWithBoundary:** Grants the power to provision identities. However, the Condition is the Enforcement Mechanism mandating that any user or role created must have the `Global-GRC-Boundary` attached, or the request is denied.
2. **AllowCreateLoginProfile:** Decoupled from the previous block because `CreateLoginProfile` (assigning a password) does not support the `PermissionsBoundary` condition key. This ensures the admin can actually grant console access once the governed user is created.
3. **AllowSelfServiceAndRead:** Follows the Principle of Least Privilege. It allows the admin to see the environment (`List*`, `Get*`) and manage their own security (Password/MFA) without granting them broad administrative rights over others' credentials.
