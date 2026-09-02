import { create } from 'zustand'
type State = { engagementId: string; setEngagementId: (id:string)=>void }
export const useStore = create<State>((set)=>({ engagementId: '', setEngagementId: (id)=> set({engagementId:id}) }))
