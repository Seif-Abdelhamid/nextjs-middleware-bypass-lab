export const dynamic = 'force-dynamic'
export default function Dashboard() {
  return (
    <main>
      <h1 data-testid="dashboard">PROTECTED DASHBOARD</h1>
      <p data-testid="secret">SECRET: internal revenue figures Q3</p>
    </main>
  )
}
