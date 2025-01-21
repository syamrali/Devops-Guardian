from dotenv import load_dotenv
import os
import streamlit as st
import google.generativeai as genai

# Load environment variables from the .env file
load_dotenv()

# Get the API key from the environment
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    st.error("Please set your Google Gemini API key.")
    st.stop()

genai.configure(api_key=GEMINI_API_KEY)


# Function to analyze with Gemini
def analyze_with_gemini(file_content):
    """
    Analyze the given DevOps configuration file for misconfigurations
    and provide remediation suggestions using Google Gemini.
    """
    try:
        prompt = f"""
        You are an AI DevOps assistant. Analyze the following configuration file for misconfigurations, 
        vulnerabilities, and best practice violations. Provide a detailed report of issues and actionable remediation steps.

        Configuration File:
        {file_content}
        """
        model = genai.GenerativeModel("gemini-1.5-flash")
        result = model.generate_content([prompt])
        return result.text
    except Exception as e:
        return f"Error: {str(e)}"


# Function to generate Kubernetes Deployment YAML from a Dockerfile
def generate_deployment_yaml(image_name):
    """
    Generate a basic Kubernetes deployment file.
    """
    deployment_yaml = f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {image_name}-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {image_name}
  template:
    metadata:
      labels:
        app: {image_name}
    spec:
      containers:
      - name: {image_name}
        image: {image_name}
        ports:
        - containerPort: 80
    """
    return deployment_yaml


# Function to generate Kubernetes Service YAML from a Dockerfile
def generate_service_yaml(image_name):
    """
    Generate a basic Kubernetes service file.
    """
    service_yaml = f"""
apiVersion: v1
kind: Service
metadata:
  name: {image_name}-service
spec:
  selector:
    app: {image_name}
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
  type: ClusterIP
    """
    return service_yaml


# Function to generate Kubernetes Ingress YAML from a Dockerfile
def generate_ingress_yaml(image_name, host_name):
    """
    Generate a basic Kubernetes ingress file.
    """
    ingress_yaml = f"""
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {image_name}-ingress
spec:
  rules:
  - host: {host_name}
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: {image_name}-service
            port:
              number: 80
    """
    return ingress_yaml


# Streamlit App
st.title("🔒 AI-DevOps Guardian")
st.subheader("Secure your DevOps configurations with AI-powered analysis.")
st.write(
    """
Upload your DevOps configuration files (e.g., YAML, JSON, Dockerfile, Terraform, Ansible, Kubernetes) to scan for:
- Misconfigurations
- Security vulnerabilities
- Best practice violations
- Actionable remediation suggestions
"""
)

# File Upload Section
uploaded_file = st.file_uploader(
    "Upload a DevOps configuration file",
    type=None,  # Allow all file types
)

if uploaded_file:
    file_name = uploaded_file.name
    file_content = uploaded_file.read().decode("utf-8")

    # Check for "Dockerfile" specifically
    if file_name == "Dockerfile" or file_name.endswith((".yaml", ".yml", ".json", ".tf", ".ini", ".conf")):
        # Display uploaded file content
        st.subheader("Uploaded File Content")
        st.code(file_content, language="plaintext")

        # Analyze Button
        if st.button("🔍 Scan for Misconfigurations"):
            with st.spinner("Analyzing with AI-DevOps Guardian..."):
                analysis_result = analyze_with_gemini(file_content)
                if analysis_result:
                    st.success("Analysis Complete!")
                    st.subheader("🛠️ Misconfiguration Report")
                    st.write(analysis_result)

        # Generate Kubernetes Files Button
        if st.button("Generate Kubernetes YAML Files"):
            with st.spinner("Generating Kubernetes files..."):
                image_name = "your-image-name"  # Replace with logic for detecting app name/image
                host_name = "your-host-name.com"  # Replace with logic for host

                deployment_yaml = generate_deployment_yaml(image_name)
                service_yaml = generate_service_yaml(image_name)
                ingress_yaml = generate_ingress_yaml(image_name, host_name)

                # Display the generated YAML files
                st.subheader("Generated Kubernetes Deployment YAML")
                st.code(deployment_yaml, language="yaml")

                st.subheader("Generated Kubernetes Service YAML")
                st.code(service_yaml, language="yaml")

                st.subheader("Generated Kubernetes Ingress YAML")
                st.code(ingress_yaml, language="yaml")

    else:
        st.error("Unsupported file type. Please upload a valid DevOps configuration file.")
else:
    st.info("Please upload a configuration file to begin analysis.")

# Footer
st.markdown("---")
st.markdown("🌟 Secure your DevOps with **AI-DevOps Guardian**")
