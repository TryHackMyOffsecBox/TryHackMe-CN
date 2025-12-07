---
sidebar_position: 2
---

# Data Integrity & Model Poisoning

## Task 1 Introduction

Modern AI systems depend heavily on the quality and trustworthiness of their data and model components. When attackers compromise training data or model parameters, they can inject hidden vulnerabilities, manipulate predictions, or bias outputs. In this room, you'll explore how these attacks work and how to detect and mitigate them using practical techniques.

### Learning Objectives

- Understand how compromised datasets or model components can lead to security risks.
- Examine common ways adversaries use to introduce malicious inputs during training or fine-tuning.
- Assess vulnerabilities in externally sourced datasets, pre-trained models, and third-party libraries.
- Practice model poisoning through the eyes of an attacker.

### Prerequisites

Data integrity and model poisoning are specialised threats within the broader field of machine learning security. To get the most out of this room, you should have a foundational understanding of how machine learning models are trained and deployed, as well as the basics of data preprocessing and model evaluation. Additionally, you should be familiar with general security principles related to supply chain and input validation.

- [AI/ML Security Threats](https://tryhackme.com/room/aimlsecuritythreats)
- [Detecting Adversarial Attacks](https://tryhackme.com/room/idadversarialattacks)

:::info Answer the questions below

<details>

<summary> I have successfully started the machine. </summary>

```plaintext
No answer needed
```

</details>

:::

## Task 2 Supply Chain Attack

In this task, we will explore how attackers exploit the supply chain (termed LLM03 in the [OWASP GenAI Security Project](https://genai.owasp.org/llmrisk/llm032025-supply-chain/)) to attack LLMs. In the context of LLM, the supply chain refers to all the external components, datasets, model weights, adapters, libraries, and infrastructure that go into training, fine-tuning, or deploying an LLM. Because many of these pieces come from third parties or open-source repositories, they create a broad attack surface where malicious actors can tamper with inputs long before a model reaches production.

### How It Occurs

- Attackers tamper with or "poison" external components used by LLM systems like pre-trained model weights, fine-tuning adapters, datasets, or third-party libraries.
- Weak provenance (e.g., poor source documentation and lack of integrity verification) makes detection harder. Attackers can disguise malicious components so that they pass standard benchmarks yet introduce hidden backdoors.

![An image of an AI response being poisoned through an untrusted data source](img/image_20251202-230237.png)

### Major Real-World Cases

- **PoisonGPT / GPT-J-6B Compromised Version**: Researchers modified an open-source model (GPT-J-6B) to include misinformation behaviour (spread fake news) while keeping it performing well on standard benchmarks. The malicious version was uploaded to Hugging Face under a name meant to look like a trusted one (typosquatting/impersonation). The modified model passed many common evaluation benchmarks almost identically to the unmodified one, so detection via standard evaluation was nearly impossible.
- [Backdooring Pre-trained Models with Embedding Indistinguishability](https://arxiv.org/abs/2401.15883): In this academic work, adversaries embed backdoors into pre-trained models, allowing downstream tasks to inherit the malicious behaviour. These backdoors are designed so that the poisoned embeddings are nearly indistinguishable from clean ones before and after fine-tuning. The experiment successfully triggered the backdoor under various conditions, highlighting how supply chain poisoning in the model weights can propagate.

### Common Examples

| Threat Type                               | Description                                                                                                                                                                                                                                                           |
| :---------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Vulnerable or outdated packages/libraries | Using old versions of ML frameworks, data pipelines, or dependencies with known vulnerabilities can allow attackers to gain entry or inject malicious behaviour. E.g., a compromised PyTorch or TensorFlow component used in fine-tuning or data preprocessing.       |
| Malicious pre-trained models or adapters  | A provider or attacker publishes a model or adapter that appears legitimate, but includes hidden malicious behaviour or bias. When downstream users use them without verifying integrity, they inherit the threat.                                                    |
| Stealthy backdoor/trigger insertion       | The insertion of triggers that only activate under certain conditions, remaining dormant otherwise, so they evade regular testing. For example, "hidden triggers" in model parameters or in embeddings, which only manifest when a specific token or pattern is used. |
| Collaborative/merged models               | Components may come from different sources, with models being merged (from multiple contributors) or using shared pipelines. Attackers may target weak links (e.g. a library or adapter) in the pipeline to introduce malicious code or backdoors.                    |

:::info Answer the questions below

<details>

<summary> What is the name of the website where the malicious version of GPT-J-6B was uploaded? </summary>

```plaintext
Hugging Face
```

</details>

<details>

<summary> What term refers to all the **external** components, datasets, model weights, adapters, libraries, and infrastructure used to train, fine-tune, or deploy an LLM? </summary>

```plaintext
Supply Chain
```

</details>

:::

## Task 3 Model Poisoning

Model poisoning is an adversarial technique where attackers deliberately inject malicious or manipulated data during a model’s training or retraining cycle. The goal is to bias the model’s behaviour, degrade its performance, or embed hidden backdoors that can be triggered later. Unlike prompt injection, this targets the model weights, making the compromise persistent.

### Prerequisite of Model Poisoning

Model poisoning isn’t possible on every system. It specifically affects models that accept user input as part of their continuous learning or fine-tuning pipeline. For example, recommender systems, chatbots, or any adaptive model that automatically re-train on user feedback or submitted content. Static, fully offline models (where training is frozen and never updated from external inputs) are generally not vulnerable. For an attack to succeed, the model must adhere to the following:

- Incorporate untrusted user data into its training corpus.
- Lack rigorous data validation.
- Redeploy updated weights without strong integrity checks.

### Cheat Sheet for Pentesters

Here is the checklist for red teamers and pentesters when assessing model poisoning risks:

- **Data ingestion pipeline**: Does the LLM or system retrain on unverified user inputs, feedback, or uploaded content?
- **Update frequency**: How often is the model fine-tuned or updated?
- **Data provenance and sanitisation**: Can training data sources be traced, and are they validated against poisoning attempts?
- **Access controls**: Who can submit data included in re-training, and is that channel exposed to untrusted users?

![image of LLM attack cycle](img/image_20251214-231442.png)

### Attack Process

- **Where**: Poisoning can occur at different stages, during pre-training (large-scale dataset poisoning), fine-tuning (targeted task manipulation), or continual learning (live re-training from user data).
- **How**: The attacker seeds malicious examples into the training set, waits for the re-training cycle, and leverages the altered model behaviour for backdoors.

:::info Answer the questions below

<details>

<summary> An adversarial technique where attackers deliberately inject malicious or manipulated data during a model’s training is called? </summary>

```plaintext
Model poisoning
```

</details>

:::

## Task 4 Model Poisoning - Challenge

## Task 5 Mitigation Measures

## Task 6 Conclusion
