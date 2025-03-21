FROM zgrab2_smtp_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Command to run postfix (in the foreground)
CMD ["postfix", "start-fg"]

