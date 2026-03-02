# file: tools/project_resolver.py
# Resolves GCP project IDs and numbers from a project, folder, or org scope.
# Returns both project_id and project_number in a single API call per project
# so downstream tools (cloud_run_scanner.py) never need to call get_project again.

from google.cloud import resourcemanager_v3


def resolve_projects(
    project_id: str = None,
    folder_id: str = None,
    org_id: str = None,
) -> list[dict]:
    """
    Resolves active GCP projects based on the provided scope.

    Args:
        project_id: A single project ID
        folder_id:  A folder ID — resolves all active projects under it
        org_id:     An org ID — resolves all active projects in the org

    Returns:
        List of dicts with:
        - project_id:     e.g. "my-project-id"
        - project_number: e.g. "123456789012"
    """
    client = resourcemanager_v3.ProjectsClient()

    if project_id:
        # Single project — fetch once to get project number
        project_info = client.get_project(name=f"projects/{project_id}")
        project_number = project_info.name.split("/")[-1]
        return [{"project_id": project_id, "project_number": project_number}]

    if folder_id:
        parent = f"folders/{folder_id}"
    elif org_id:
        parent = f"organizations/{org_id}"
    else:
        return []

    query = f"parent:{parent} state:ACTIVE"
    request = resourcemanager_v3.SearchProjectsRequest(query=query)

    projects = []
    for project in client.search_projects(request=request):
        project_number = project.name.split("/")[-1]
        projects.append({
            "project_id": project.project_id,
            "project_number": project_number,
        })

    return projects
