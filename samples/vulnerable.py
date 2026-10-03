import subprocess

password = "demo-secret"

def run(user_input):
    return eval(user_input)

subprocess.run("echo " + password, shell=True)
