import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
import os
import yaml

# Load environment variables and configure Gemini
load_dotenv()
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
def generate_deployment_yaml(image_name, dockerfile_config=None):
    """
    Generate a Kubernetes deployment file using Dockerfile analysis.
    """
    if dockerfile_config is None:
        dockerfile_config = {}
    
    # Extract configuration from Dockerfile analysis
    ports = dockerfile_config.get('ports', [80])
    env_vars = dockerfile_config.get('env_vars', [])
    volumes = dockerfile_config.get('volumes', [])
    resources = dockerfile_config.get('resources', {})
    command = dockerfile_config.get('command', None)
    
    container_spec = {
        'name': image_name,
        'image': image_name,
        'ports': [{'containerPort': port} for port in ports]
    }
    
    # Add environment variables if present
    if env_vars:
        container_spec['env'] = [{'name': env['name'], 'value': env['value']} for env in env_vars]
    
    # Add command if present
    if command:
        container_spec['command'] = command if isinstance(command, list) else [command]
    
    # Convert container_spec to formatted string
    container_spec_str = ''.join(f'        {k}: {v}\n' for k, v in container_spec.items())
    
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
      - {container_spec_str}"""
    
    return deployment_yaml


# Function to generate Kubernetes Service YAML from a Dockerfile
def generate_service_yaml(image_name, dockerfile_config=None):
    """
    Generate a Kubernetes service file using Dockerfile analysis.
    """
    if dockerfile_config is None:
        dockerfile_config = {}
    
    ports = dockerfile_config.get('ports', [80])
    
    ports_spec = '\n'.join(f'    - protocol: TCP\n      port: {port}\n      targetPort: {port}' for port in ports)
    
    service_yaml = f"""
apiVersion: v1
kind: Service
metadata:
  name: {image_name}-service
spec:
  selector:
    app: {image_name}
  ports:
{ports_spec}
  type: ClusterIP"""
    
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


def analyze_dockerfile(file_content):
    model = genai.GenerativeModel('gemini-pro')
    prompt = f"""
    Analyze the following Dockerfile and extract key configuration details in JSON format:
    {file_content}
    
    Return a JSON object with these fields:
    - base_image: The base image used
    - ports: List of exposed ports
    - env_vars: List of environment variables
    - volumes: List of volumes
    - command: Default command or entrypoint
    - resources: Any resource specifications found
    """
    response = model.generate_content(prompt)
    try:
        # Store the raw analysis for display
        st.session_state.raw_analysis = response.text
        # Try to extract structured data from the response
        import json
        # Look for JSON-like content between triple backticks if present
        import re
        json_match = re.search(r'```json\n(.*?)\n```', response.text, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(1))
        # If no backticks, try parsing the entire response
        return json.loads(response.text)
    except Exception as e:
        st.error(f"Failed to parse Dockerfile analysis: {str(e)}")
        return {}


def is_dockerfile(file_name, file_content):
    """Validate if the uploaded file is a Dockerfile"""
    if file_name.lower() == "dockerfile":
        return True
    # Check if the content looks like a Dockerfile
    dockerfile_keywords = ["FROM", "RUN", "CMD", "ENTRYPOINT", "COPY", "ADD", "ENV", "WORKDIR", "EXPOSE"]
    content_lines = file_content.upper().split('\n')
    return any(line.strip().startswith(tuple(dockerfile_keywords)) for line in content_lines)


# Main App
st.title("DevOps Tools Suite")

# Create option menu
tool_option = st.sidebar.selectbox(
    "Select Tool",
    ["🔒 AI-DevOps Guardian", "⚙️ Kubernetes YAML Generator"]
)

if tool_option == "🔒 AI-DevOps Guardian":
    st.header("AI-DevOps Guardian")
    st.subheader("Secure your DevOps configurations with AI-powered analysis.")
    st.write("""
    Upload your DevOps configuration files to scan for:
    - Misconfigurations
    - Security vulnerabilities
    - Best practice violations
    - Actionable remediation suggestions
    """)
    
    uploaded_file = st.file_uploader(
        "Upload a DevOps configuration file",
        type=None,
        key="guardian_uploader"
    )

    if uploaded_file:
        file_name = uploaded_file.name
        file_content = uploaded_file.read().decode("utf-8")

        if file_name == "Dockerfile" or file_name.endswith((".yaml", ".yml", ".json", ".tf", ".ini", ".conf")):
            st.subheader("Uploaded File Content")
            st.code(file_content, language="plaintext")

            if st.button("🔍 Scan for Misconfigurations"):
                with st.spinner("Analyzing with AI-DevOps Guardian..."):
                    analysis_result = analyze_with_gemini(file_content)
                    if analysis_result:
                        st.success("Analysis Complete!")
                        st.subheader("🛠️ Misconfiguration Report")
                        st.write(analysis_result)
        else:
            st.error("Unsupported file type. Please upload a valid DevOps configuration file.")

elif tool_option == "⚙️ Kubernetes YAML Generator":
    st.header("Kubernetes YAML Generator")
    st.subheader("Generate Kubernetes configurations from your Dockerfile")
    
    # Step 1: Upload Dockerfile
    step = st.session_state.get('k8s_step', 1)
    
    if step == 1:
        st.write("### Step 1: Upload your Dockerfile")
        st.info("Please upload a Dockerfile to generate Kubernetes configurations.")
        
        uploaded_file = st.file_uploader(
            "Upload Dockerfile",
            type=None,  # Allow all file types, we'll validate manually
            key="dockerfile_uploader",
            help="Upload a Dockerfile (named 'Dockerfile' without extension)"
        )
        
        if uploaded_file:
            file_content = uploaded_file.read().decode("utf-8")
            
            # Validate if it's a Dockerfile
            if is_dockerfile(uploaded_file.name, file_content):
                st.success("✅ Valid Dockerfile detected")
                st.write("#### Dockerfile Contents:")
                st.code(file_content, language="dockerfile")
                
                if st.button("Analyze Dockerfile"):
                    with st.spinner("Analyzing Dockerfile..."):
                        analysis = analyze_dockerfile(file_content)
                        st.session_state.dockerfile_analysis = analysis
                        st.session_state.k8s_step = 2
                        st.rerun()
            else:
                st.error("❌ Invalid file. Please upload a valid Dockerfile.")
                st.stop()
    
    # Step 2: Review Analysis and Configure
    elif step == 2:
        st.write("### Step 2: Review Analysis and Configure Settings")
        
        # Display Dockerfile analysis in a nice format
        st.write("#### 📋 Dockerfile Analysis")
        with st.expander("View Dockerfile Analysis", expanded=True):
            st.write(st.session_state.dockerfile_analysis)
        
        
        st.write("#### ⚙️ Configure Kubernetes Settings")
        col1, col2 = st.columns(2)
        with col1:
            image_name = st.text_input(
                "Container Image Name",
                "my-app",
                help="Name of your container image (e.g., my-app)"
            )
        with col2:
            host_name = st.text_input(
                "Host Name",
                "example.com",
                help="Domain name for your application"
            )
        if st.button("Generate Kubernetes Files"):
            if image_name and host_name:
                st.session_state.image_name = image_name
                st.session_state.host_name = host_name
                st.session_state.k8s_step = 3
                st.rerun()
            else:
                st.error("Please fill in all required fields.")
        
    # Step 3: Generate and Download
    elif step == 3:
        st.write("### Step 3: Generated Kubernetes Files")
        
        image_name = st.session_state.image_name
        host_name = st.session_state.host_name
        dockerfile_config = st.session_state.get('dockerfile_analysis', {})
        
        # Generate YAML files using Dockerfile configuration
        deployment_yaml = generate_deployment_yaml(image_name, dockerfile_config)
        service_yaml = generate_service_yaml(image_name, dockerfile_config)
        ingress_yaml = generate_ingress_yaml(image_name, host_name)
        
        # Display files in expandable sections
        with st.expander("📄 Deployment YAML", expanded=True):
            st.code(deployment_yaml, language="yaml")
            st.download_button(
                "⬇️ Download Deployment YAML",
                deployment_yaml,
                file_name=f"{image_name}-deployment.yaml",
                mime="text/yaml"
            )
        
        with st.expander("📄 Service YAML", expanded=True):
            st.code(service_yaml, language="yaml")
            st.download_button(
                "⬇️ Download Service YAML",
                service_yaml,
                file_name=f"{image_name}-service.yaml",
                mime="text/yaml"
            )
            
        with st.expander("📄 Ingress YAML", expanded=True):
            st.code(ingress_yaml, language="yaml")
            st.download_button(
                "⬇️ Download Ingress YAML",
                ingress_yaml,
                file_name=f"{image_name}-ingress.yaml",
                mime="text/yaml"
            )    
    
        
        
        
     

        # Option to restart
        if st.button("🔄 Start Over"):
            st.session_state.k8s_step = 1
            st.rerun()

# Initialize session state if needed
if 'k8s_step' not in st.session_state:
    st.session_state.k8s_step = 1

# Footer
st.markdown("---")
st.markdown("🌟 DevOps Tools Suite - Making DevOps easier")
