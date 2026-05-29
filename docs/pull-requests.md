Microsoft ADO policy disables automatic PR-build runs to prevent unreviewed
code (e.g. from external forks) from executing on internal pipeline agents.
To start the pull request build pipeline on any PR into `main`, a Microsoft
employee must comment on the pull request. The comment must only contain
`/azp run`. This will signal to the azure-pipelines bot to start the PR build
pipeline.

Name of the PR build pipeline:

- `MXC-PR-Build`

To check the status of this pipeline in Azure DevOps you can navigate to 
[MXC-PR-Build](https://microsoft.visualstudio.com/Dart/_build?definitionId=192146).